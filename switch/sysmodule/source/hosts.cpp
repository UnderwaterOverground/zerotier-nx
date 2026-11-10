// See hosts.hpp.
#include <stratosphere.hpp>

#include <arpa/inet.h>

#include <algorithm>
#include <cstring>
#include <memory>

#include "hosts.hpp"
#include "log.hpp"
#include "vsock.hpp"

namespace ams::hosts {

    namespace {

        constexpr const char BeginMarker[] = "# >>> zerotier-nx: peer names, rewritten automatically; edit outside this block >>>\n";
        constexpr const char EndMarker[] = "# <<< zerotier-nx <<<\n";

        // Atmosphère aborts (taking the console down) on a hosts file of
        // 32 KB or more, or a name of 512+ bytes; stay well clear of both.
        constexpr size_t MaxFile = 24_KB;
        constexpr size_t MaxBlock = 8_KB;
        constexpr size_t MaxName = 253;

        // The block last written (FNV-1a), to skip rewriting an unchanged one.
        constinit u64 g_last_block_hash = 0;

        // Built by Collect(), for Write().
        constinit char *g_block = nullptr;
        constinit size_t g_block_len = 0;
        constinit int g_block_count = 0;
        constinit u64 g_block_hash = 0;

        u64 Hash(const char *p, size_t n) {
            u64 h = 0xcbf29ce484222325ull;
            for (size_t i = 0; i < n; i++) h = (h ^ static_cast<u8>(p[i])) * 0x100000001b3ull;
            return h;
        }

        // The file Atmosphère's dns_mitm reads (its SelectHostsFile), among
        // those that exist; false if none does (then we leave it alone:
        // creating a higher-priority file would hide the user's).
        bool SelectPath(char *out, size_t cap) {
            auto exists = [](const char *p) {
                fs::DirectoryEntryType t;
                return R_SUCCEEDED(fs::GetEntryType(std::addressof(t), p)) && t == fs::DirectoryEntryType_File;
            };
            if (emummc::IsActive()) {
                util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/emummc_%04x.txt", emummc::GetActiveId());
                if (exists(out)) return true;
                util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/emummc.txt");
                if (exists(out)) return true;
            } else {
                util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/sysmmc.txt");
                if (exists(out)) return true;
            }
            util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/default.txt");
            return exists(out);
        }

        bool ValidName(const char *s, size_t n) {
            if (n == 0 || n > MaxName || s[0] == '.' || s[0] == '-') return false;
            for (size_t i = 0; i < n; i++) {
                const char c = s[i];
                const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
                if (!ok) return false;
            }
            // Atmosphère checks later entries first, so ours (the file's
            // last block) win: never add names that could shadow anything
            // else. Exact names only match themselves, but a peer called
            // "localhost" would still take that name over.
            if (n == 9 && std::strncmp(s, "localhost", 9) == 0) return false;
            // Nor anything that could look like a Nintendo host.
            for (size_t i = 0; i + 8 <= n; i++) {
                bool match = true;
                for (size_t j = 0; j < 8 && match; j++) match = (s[i + j] | 0x20) == "nintendo"[j];
                if (match) return false;
            }
            return true;
        }

        // Builds the managed block from "ip name\n" lines. Returns its length
        // (0: no valid entries).
        size_t BuildBlock(const char *lines, char *out, size_t cap, int *count) {
            size_t n = util::SNPrintf(out, cap, "%s", BeginMarker);
            *count = 0;
            for (const char *line = lines; *line;) {
                const char *eol = std::strchr(line, '\n');
                const size_t len = eol ? static_cast<size_t>(eol - line) : std::strlen(line);
                const char *sp = static_cast<const char *>(std::memchr(line, ' ', len));
                if (sp) {
                    const size_t ip_len = static_cast<size_t>(sp - line), name_len = len - ip_len - 1;
                    const char *name = sp + 1;
                    const char *dot = static_cast<const char *>(std::memchr(name, '.', name_len));
                    const size_t short_len = dot ? static_cast<size_t>(dot - name) : 0;
                    if (ip_len <= 15 && ValidName(name, name_len)) {
                        char entry[600];
                        int m = util::SNPrintf(entry, sizeof entry, "%.*s %.*s", static_cast<int>(ip_len), line, static_cast<int>(name_len), name);
                        if (short_len > 0 && ValidName(name, short_len)) {
                            m += util::SNPrintf(entry + m, sizeof entry - m, " %.*s", static_cast<int>(short_len), name);
                        }
                        m += util::SNPrintf(entry + m, sizeof entry - m, "\n");
                        if (n + m + sizeof EndMarker >= cap) break;  // block full: keep what fits
                        std::memcpy(out + n, entry, m);
                        n += m;
                        ++*count;
                    }
                }
                line += eol ? len + 1 : len;
            }
            n += util::SNPrintf(out + n, cap - n, "%s", EndMarker);
            return *count > 0 ? n : 0;
        }

        // Removes a previous block (both markers present) from text[0..len).
        size_t StripBlock(char *text, size_t len) {
            char *begin = std::strstr(text, BeginMarker);
            if (!begin) return len;
            char *end = std::strstr(begin, EndMarker);
            if (!end) return len;  // half a block: leave the file as it is
            end += sizeof EndMarker - 1;
            std::memmove(begin, end, text + len - end + 1);
            return len - static_cast<size_t>(end - begin);
        }

        void ReloadAtmosphereHosts() {
            ::Service srv;
            if (R_FAILED(smGetService(std::addressof(srv), "sfdnsres"))) return;
            // 65000: AtmosphereReloadHostsFile (Atmosphère dns_mitm only).
            const ::Result rc = serviceDispatch(std::addressof(srv), 65000);
            serviceClose(std::addressof(srv));
            if (R_FAILED(rc)) Log("hosts: Atmosphere did not reload (dns_mitm disabled?): 0x%x", rc);
        }

        // Gives each private peer address in "ip name\n" lines a stand-in
        // (VSock::AliasFor) and tells the socket layer about them. Never our
        // own address, a stand-in that collides with another or falls in a
        // tunnel route, or more than VSock::MaxAliases.
        void Alias(const ZtnxNetConfig &net, char *lines, size_t cap) {
            auto out = std::make_unique<char[]>(cap);
            // The network's routes, as the socket layer has them (see
            // ZtLink::Apply): our subnets and the managed routes.
            auto routes = std::make_unique<ZtnxPrefix[]>(::ztnx::VSock::MaxRoutes);
            size_t n_routes = 0;
            auto add = [&](const u8 ip[4], u8 len) {
                if (n_routes >= ::ztnx::VSock::MaxRoutes || len == 0) return;
                ZtnxPrefix &p = routes[n_routes++];
                std::memset(std::addressof(p), 0, sizeof p);
                p.family = 4;
                p.len = len;
                std::memcpy(p.ip, ip, 4);
            };
            for (unsigned i = 0; i < net.n_addrs; i++) add(net.addrs[i].ip, net.addrs[i].prefix);
            for (unsigned i = 0; i < net.n_routes; i++) add(net.routes[i].target, net.routes[i].prefix);
            ZtnxPrefix own[ZTNX_MAX_ADDRS];
            const size_t n_own = net.n_addrs;
            for (unsigned i = 0; i < net.n_addrs; i++) {
                std::memset(std::addressof(own[i]), 0, sizeof own[i]);
                own[i].family = 4;
                own[i].len = 32;
                std::memcpy(own[i].ip, net.addrs[i].ip, 4);
            }
            auto in_prefix = [](u32 ip, const ZtnxPrefix &p) {
                if (p.family != 4 || p.len > 32) return false;
                u32 net;
                std::memcpy(std::addressof(net), p.ip, 4);
                const u32 mask = p.len ? ~0u << (32 - p.len) : 0;
                return (ip & mask) == (ntohl(net) & mask);
            };
            ::ztnx::VSock::Alias aliases[::ztnx::VSock::MaxAliases];
            size_t n_aliases = 0, o = 0;
            for (const char *line = lines; *line && o + 1 < cap;) {
                const char *eol = std::strchr(line, '\n');
                const size_t len = eol ? static_cast<size_t>(eol - line) : std::strlen(line);
                const char *sp = static_cast<const char *>(std::memchr(line, ' ', len));
                char ip_text[16] = {};
                in_addr real{};
                u32 alias = 0;
                if (sp && static_cast<size_t>(sp - line) < sizeof ip_text) {
                    std::memcpy(ip_text, line, static_cast<size_t>(sp - line));
                    real.s_addr = inet_addr(ip_text);  // INADDR_NONE (a bad one) isn't private
                    alias = ::ztnx::VSock::AliasFor(ntohl(real.s_addr));
                }
                for (size_t i = 0; alias && i < n_own; i++)
                    if (own[i].family == 4 && std::memcmp(own[i].ip, std::addressof(real.s_addr), 4) == 0) alias = 0;
                for (size_t i = 0; alias && i < n_routes; i++)
                    if (in_prefix(alias, routes[i])) alias = 0;
                for (size_t i = 0; alias && i < n_aliases; i++)
                    if (aliases[i].alias == alias || aliases[i].real == ntohl(real.s_addr)) alias = 0;
                if (n_aliases == ::ztnx::VSock::MaxAliases) alias = 0;
                int m;
                if (alias) {
                    aliases[n_aliases++] = {alias, ntohl(real.s_addr)};
                    Log("hosts: %.*s named as %u.%u.%u.%u, a stand-in for %s", static_cast<int>(len - static_cast<size_t>(sp - line) - 1), sp + 1, alias >> 24,
                        (alias >> 16) & 0xff, (alias >> 8) & 0xff, alias & 0xff, ip_text);
                    m = util::SNPrintf(out.get() + o, cap - o, "%u.%u.%u.%u%.*s\n", alias >> 24, (alias >> 16) & 0xff, (alias >> 8) & 0xff, alias & 0xff,
                                       static_cast<int>(len - static_cast<size_t>(sp - line)), sp);
                } else {
                    m = util::SNPrintf(out.get() + o, cap - o, "%.*s\n", static_cast<int>(len), line);
                }
                if (m < 0 || o + static_cast<size_t>(m) >= cap) break;
                o += static_cast<size_t>(m);
                line += eol ? len + 1 : len;
            }
            out[o] = 0;
            std::memcpy(lines, out.get(), o + 1);
            ::ztnx::VSock::SetAliases(aliases, n_aliases);
        }

    }

    bool Collect(const char *names, const ZtnxNetConfig &net, bool aliases) {
        // Runs rarely: working buffers come from the heap, not static memory.
        auto lines = std::make_unique<char[]>(MaxBlock);
        auto block = std::make_unique<char[]>(MaxBlock);
        util::SNPrintf(lines.get(), MaxBlock, "%s", names);
        if (aliases) Alias(net, lines.get(), MaxBlock);
        else ::ztnx::VSock::SetAliases(nullptr, 0);
        int count = 0;
        const size_t block_len = BuildBlock(lines.get(), block.get(), MaxBlock, std::addressof(count));
        const u64 hash = Hash(block.get(), block_len);
        if (hash == g_last_block_hash) return false;
        delete[] g_block;
        g_block = block.release();
        g_block_len = block_len;
        g_block_count = count;
        g_block_hash = hash;
        return true;
    }

    void Write() {
        if (!g_block) return;
        const std::unique_ptr<char[]> block(g_block);
        g_block = nullptr;
        const size_t block_len = g_block_len;
        const int count = g_block_count;
        const u64 hash = g_block_hash;

        char path[0x60];
        if (!SelectPath(path, sizeof path)) {
            Log("hosts: no Atmosphere hosts file to add peer names to");
            return;
        }

        // Read the whole file; anything unexpected means we don't write.
        auto text = std::make_unique<char[]>(MaxFile + MaxBlock + 2);
        fs::FileHandle f;
        if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) return;
        s64 size = 0;
        size_t got = 0;
        const bool read_ok = R_SUCCEEDED(fs::GetFileSize(std::addressof(size), f)) && size >= 0 && static_cast<size_t>(size) <= MaxFile &&
                             R_SUCCEEDED(fs::ReadFile(std::addressof(got), f, 0, text.get(), static_cast<size_t>(size))) &&
                             got == static_cast<size_t>(size);
        fs::CloseFile(f);
        if (!read_ok) {
            Log("hosts: %s is unreadable or over %zu KB; not touching it", path, MaxFile / 1024);
            return;
        }
        text[got] = 0;
        if (std::strlen(text.get()) != got) return;  // embedded NUL: not a text file we understand

        size_t len = StripBlock(text.get(), got);
        if (len > 0 && text[len - 1] != '\n') text[len++] = '\n';
        std::memcpy(text.get() + len, block.get(), block_len);
        len += block_len;
        if (len > MaxFile) {
            Log("hosts: %s would grow past %zu KB; not adding peer names", path, MaxFile / 1024);
            return;
        }

        // In place (write, then trim), so the file never goes missing: a
        // reload that can't open it aborts Atmosphère's dns_mitm.
        if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) return;
        const bool ok = R_SUCCEEDED(fs::WriteFile(f, 0, text.get(), len, fs::WriteOption::Flush)) && R_SUCCEEDED(fs::SetFileSize(f, static_cast<s64>(len)));
        static_cast<void>(fs::FlushFile(f));
        fs::CloseFile(f);
        if (!ok) {
            Log("hosts: writing %s failed", path);
            return;
        }
        g_last_block_hash = hash;
        ReloadAtmosphereHosts();
        Log("hosts: %d peer names in %s", count, path);
    }

}
