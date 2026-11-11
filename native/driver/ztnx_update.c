// See ztnx_update.h.
#include "ztnx_update.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ztnx.h"
#include "ztnx_dns.h"

// TLS: on the Switch the console's own ssl service does it (its code and
// its handshake memory are the system's, not ours); elsewhere the Rust
// client in ztnx-core.
#ifdef __SWITCH__
#include <switch.h>

#include "ztnx_update_roots.h"
#endif

#ifdef ZTNX_NO_STDIO
// Builds without newlib's printf (the sysmodule) supply this instead.
int ztnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf ztnx_snprintf
#endif

#define HOST ZTNX_UPDATE_HOST

struct ZtnxUpdate {
    int fd;
#ifdef __SWITCH__
    SslContext ctx;
    SslConnection conn;
    int ssl_up, ctx_up, conn_up;  // what ztnx_update_free has to undo
    int stage;                    // SSL_*
    char req[256];
    size_t req_len, req_off;
#else
    ZtnxTls *tls;
#endif
    int connecting;
    int result;
    uint64_t deadline_ns;
    char current[24];
    char latest[24];
    char error[96];
#ifndef __SWITCH__
    uint8_t out[1024];  // ciphertext taken from TLS, not yet sent
    size_t out_off, out_len;
#endif
    char head[1024];    // the response's start; the Location header is early
    size_t head_len;
};

static int fail(ZtnxUpdate *u, const char *what, const char *detail) {
    snprintf(u->error, sizeof u->error, "%s%s%s", what, detail ? ": " : "", detail ? detail : "");
    u->result = ZTNX_UPDATE_FAILED;
    return u->result;
}

// No strerror: its message table would grow the sysmodule.
static int fail_errno(ZtnxUpdate *u, const char *what, int err) {
    char detail[24];
    snprintf(detail, sizeof detail, "errno %d", err);
    return fail(u, what, detail);
}

ZtnxUpdate *ztnx_update_start(const char *repo, const char *current, uint64_t now_ns, uint32_t timeout_ms) {
    ZtnxUpdate *u = (ZtnxUpdate *)calloc(1, sizeof *u);
    if (!u) return NULL;
    u->fd = -1;
    u->deadline_ns = now_ns + (uint64_t)timeout_ms * 1000000ull;
    snprintf(u->current, sizeof u->current, "%s", current);

    uint32_t ip;
    if (ztnx_resolve_ipv4(HOST, &ip) != 0) {
        fail(u, "cannot resolve " HOST, NULL);
        return u;
    }
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons(443);
    u->fd = socket(AF_INET, SOCK_STREAM, 0);
    int flags = u->fd < 0 ? -1 : fcntl(u->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(u->fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        fail_errno(u, "no socket", errno);
        return u;
    }
    // We send a few hundred bytes: keep our share of the socket buffer pool small.
    const int snd = 0x2000;
    setsockopt(u->fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
    if (connect(u->fd, (struct sockaddr *)&sin, sizeof sin) != 0 && errno != EINPROGRESS) {
        fail_errno(u, "connect", errno);
        return u;
    }
    u->connecting = 1;

    // Sent once the handshake is done.
#ifdef __SWITCH__
    char *req = u->req;
    const size_t req_cap = sizeof u->req;
#else
    char req_buf[256];
    char *req = req_buf;
    const size_t req_cap = sizeof req_buf;
    u->tls = ztnx_tls_new(HOST);
    if (!u->tls) {
        fail(u, "TLS setup failed", NULL);
        return u;
    }
#endif
    const int n = snprintf(req, req_cap,
                           "GET /%s/releases/latest HTTP/1.1\r\n"
                           "Host: " HOST "\r\n"
                           "User-Agent: zerotier-nx/%s\r\n"
                           "Connection: close\r\n\r\n",
                           repo, current);
    if (n <= 0 || (size_t)n >= req_cap) {
        fail(u, "request too long", NULL);
        return u;
    }
#ifdef __SWITCH__
    u->req_len = (size_t)n;
#else
    if (ztnx_tls_write(u->tls, (const uint8_t *)req, (size_t)n) != 0) fail(u, "TLS write failed", NULL);
#endif
    return u;
}

// Finds header `name` (with the colon, any case) in the response head.
static const char *find_header(const char *head, const char *name) {
    const size_t len = strlen(name);
    for (const char *p = strstr(head, "\r\n"); p; p = strstr(p + 2, "\r\n")) {
        if (strncasecmp(p + 2, name, len) == 0) return p + 2 + len;
    }
    return NULL;
}

// The head is complete (or as much as we keep): read the redirect.
static int parse_head(ZtnxUpdate *u) {
    if (strncmp(u->head, "HTTP/1.1 302", 12) != 0 && strncmp(u->head, "HTTP/1.0 302", 12) != 0) {
        const char *eol = strstr(u->head, "\r\n");
        char status[40];
        snprintf(status, sizeof status, "%.*s", eol ? (int)(eol - u->head) : 0, u->head);
        return fail(u, "unexpected answer", status);
    }
    const char *loc = find_header(u->head, "Location:");
    const char *tag = loc ? strstr(loc, "/releases/tag/") : NULL;
    const char *eol = loc ? strstr(loc, "\r\n") : NULL;
    if (!tag || (eol && tag > eol)) return fail(u, "no release tag in the redirect", NULL);  // e.g. no releases yet
    tag += strlen("/releases/tag/");
    if (*tag == 'v' || *tag == 'V') tag++;
    size_t n = 0;
    // Only what a version contains: it ends up in a JSON toast.
    while (n + 1 < sizeof u->latest && ((tag[n] >= '0' && tag[n] <= '9') || tag[n] == '.' || tag[n] == '-' ||
                                        (tag[n] >= 'a' && tag[n] <= 'z') || (tag[n] >= 'A' && tag[n] <= 'Z'))) {
        u->latest[n] = tag[n];
        n++;
    }
    u->latest[n] = 0;
    if (n == 0 || u->latest[0] < '0' || u->latest[0] > '9') return fail(u, "unexpected release tag", NULL);
    u->result = ztnx_version_compare(u->latest, u->current) > 0 ? ZTNX_UPDATE_NEWER : ZTNX_UPDATE_CURRENT;
    return u->result;
}

#ifdef __SWITCH__
enum { SSL_SETUP, SSL_HANDSHAKE, SSL_SEND, SSL_RECV };

// The ssl service's "try again" in non-blocking mode.
static int would_block(Result rc) { return R_VALUE(rc) == MAKERESULT(123, 204); }

static int fail_rc(ZtnxUpdate *u, const char *what, Result rc) {
    char detail[24];
    snprintf(detail, sizeof detail, "0x%x", (unsigned)R_VALUE(rc));
    return fail(u, what, detail);
}

// Hands the connected socket to the ssl service and sets the connection up.
static int ssl_setup(ZtnxUpdate *u) {
    Result rc = sslInitialize(3);
    if (R_FAILED(rc)) return fail_rc(u, "ssl service", rc);
    u->ssl_up = 1;
    if (R_FAILED(rc = sslCreateContext(&u->ctx, SslVersion_Auto))) return fail_rc(u, "ssl context", rc);
    u->ctx_up = 1;
    // github.com's roots, next to the console's own store (older firmware
    // doesn't have them). A failed import just leaves that store.
    sslContextImportServerPki(&u->ctx, kRootUserTrustEcc, sizeof kRootUserTrustEcc, SslCertificateFormat_Der, NULL);
    sslContextImportServerPki(&u->ctx, kRootSectigoE46, sizeof kRootSectigoE46, SslCertificateFormat_Der, NULL);
    if (R_FAILED(rc = sslContextCreateConnection(&u->ctx, &u->conn))) return fail_rc(u, "ssl connection", rc);
    u->conn_up = 1;
    // The socket stays ours to close.
    if (R_FAILED(rc = sslConnectionSetOption(&u->conn, SslOptionType_DoNotCloseSocket, true))) return fail_rc(u, "ssl option", rc);
    if (socketSslConnectionSetSocketDescriptor(&u->conn, u->fd) == -1 && errno != ENOENT) return fail_errno(u, "ssl socket", errno);
    if (R_FAILED(rc = sslConnectionSetHostName(&u->conn, HOST, (u32)strlen(HOST)))) return fail_rc(u, "ssl host name", rc);
    // The default checks stay (the certificate chain and the host name).
    // Certificate dates are not among them, so a console with a wrong
    // clock can still ask.
    if (R_FAILED(rc = sslConnectionSetIoMode(&u->conn, SslIoMode_NonBlocking))) return fail_rc(u, "ssl mode", rc);
    u->stage = SSL_HANDSHAKE;
    return ZTNX_UPDATE_PENDING;
}

static int ssl_step(ZtnxUpdate *u) {
    Result rc;
    u32 n = 0;
    if (u->stage == SSL_SETUP && ssl_setup(u) != ZTNX_UPDATE_PENDING) return u->result;
    if (u->stage == SSL_HANDSHAKE) {
        rc = sslConnectionDoHandshake(&u->conn, NULL, NULL, NULL, 0);
        if (R_FAILED(rc)) return would_block(rc) ? ZTNX_UPDATE_PENDING : fail_rc(u, "TLS handshake", rc);
        u->stage = SSL_SEND;
    }
    while (u->stage == SSL_SEND) {
        rc = sslConnectionWrite(&u->conn, u->req + u->req_off, (u32)(u->req_len - u->req_off), &n);
        if (R_FAILED(rc)) return would_block(rc) ? ZTNX_UPDATE_PENDING : fail_rc(u, "TLS write", rc);
        u->req_off += n;
        if (u->req_off >= u->req_len) u->stage = SSL_RECV;
    }
    for (;;) {
        const size_t room = sizeof u->head - 1 - u->head_len;
        if (strstr(u->head, "\r\n\r\n") || room == 0) return parse_head(u);
        rc = sslConnectionRead(&u->conn, u->head + u->head_len, (u32)room, &n);
        if (R_FAILED(rc) && would_block(rc)) return ZTNX_UPDATE_PENDING;
        if (R_FAILED(rc) || n == 0) {
            // Closed (or broken): what arrived may still hold the answer.
            if (u->head_len) return parse_head(u);
            return R_FAILED(rc) ? fail_rc(u, "TLS read", rc) : fail(u, "connection closed", NULL);
        }
        u->head_len += n;
        u->head[u->head_len] = 0;
    }
}
#endif

int ztnx_update_step(ZtnxUpdate *u, uint64_t now_ns) {
    if (u->result != ZTNX_UPDATE_PENDING) return u->result;
    if (now_ns > u->deadline_ns) return fail(u, "timed out", NULL);

    if (u->connecting) {
        struct pollfd pfd = {u->fd, POLLOUT, 0};
        if (poll(&pfd, 1, 0) <= 0) return ZTNX_UPDATE_PENDING;
        int err = 0;
        socklen_t len = sizeof err;
        if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) err = errno;
        if (err) return fail_errno(u, "connect", err);
        u->connecting = 0;
    }

#ifdef __SWITCH__
    return ssl_step(u);
#else
    for (int progressed = 1; progressed;) {
        progressed = 0;
        // Send what TLS has for the server.
        for (;;) {
            if (u->out_off == u->out_len) {
                u->out_off = 0;
                u->out_len = ztnx_tls_take_outgoing(u->tls, u->out, sizeof u->out);
                if (u->out_len == 0) break;
            }
            const ssize_t n = send(u->fd, u->out + u->out_off, u->out_len - u->out_off, 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n <= 0) return fail_errno(u, "send", n < 0 ? errno : 0);
            u->out_off += (size_t)n;
        }
        // Receive and decrypt.
        uint8_t buf[2048];
        const ssize_t got = recv(u->fd, buf, sizeof buf, 0);
        if (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return fail_errno(u, "recv", errno);
        if (got > 0) {
            progressed = 1;
            if (ztnx_tls_feed(u->tls, buf, (size_t)got) != 0) return fail(u, "TLS", ztnx_tls_last_error(u->tls));
        }
        if (ztnx_tls_state(u->tls) & ZTNX_TLS_FAILED) return fail(u, "TLS", ztnx_tls_last_error(u->tls));
        const size_t room = sizeof u->head - 1 - u->head_len;
        if (room > 0) {
            u->head_len += ztnx_tls_read(u->tls, (uint8_t *)u->head + u->head_len, room);
            u->head[u->head_len] = 0;
        }
        if (strstr(u->head, "\r\n\r\n") || u->head_len == sizeof u->head - 1) return parse_head(u);
        if (got == 0 || (ztnx_tls_state(u->tls) & ZTNX_TLS_PEER_CLOSED)) {
            return u->head_len ? parse_head(u) : fail(u, "connection closed", NULL);
        }
    }
    return ZTNX_UPDATE_PENDING;
#endif
}

const char *ztnx_update_latest(const ZtnxUpdate *u) { return u->latest; }

const char *ztnx_update_error(const ZtnxUpdate *u) { return u->error; }

void ztnx_update_free(ZtnxUpdate *u) {
    if (!u) return;
#ifdef __SWITCH__
    if (u->conn_up) sslConnectionClose(&u->conn);
    if (u->ctx_up) sslContextClose(&u->ctx);
    if (u->ssl_up) sslExit();
    if (u->fd >= 0) close(u->fd);
#else
    if (u->fd >= 0) close(u->fd);
    if (u->tls) ztnx_tls_free(u->tls);
#endif
    free(u);
}

int ztnx_version_compare(const char *a, const char *b) {
    for (;;) {
        unsigned long x = 0, y = 0;
        while (*a >= '0' && *a <= '9') x = x * 10 + (unsigned long)(*a++ - '0');
        while (*b >= '0' && *b <= '9') y = y * 10 + (unsigned long)(*b++ - '0');
        if (x != y) return x < y ? -1 : 1;
        const int more_a = *a == '.', more_b = *b == '.';
        if (!more_a && !more_b) return 0;
        if (more_a) a++;
        if (more_b) b++;
    }
}
