// See ztnx_app.h.
#include "ztnx_app.h"
#include "ztnx_dns.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef ZTNX_NO_STDIO
// Builds without newlib's printf (the sysmodule) supply this instead.
int ztnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf ztnx_snprintf
#endif

#ifndef ZTNX_BUILD_UNIX
#error "define ZTNX_BUILD_UNIX (build time, Unix seconds)"
#endif

// Hand-rolled parsing throughout: sscanf would pull newlib's whole scanf
// (with float support) into the sysmodule.
// Parses a decimal number of at most `max_digits`; returns the rest or NULL.
static const char *parse_uint(const char *s, unsigned max_digits, unsigned *out) {
    unsigned v = 0, n = 0;
    while (*s >= '0' && *s <= '9' && n < max_digits) {
        v = v * 10 + (unsigned)(*s++ - '0');
        n++;
    }
    if (n == 0) return NULL;
    *out = v;
    return s;
}

static const char *expect(const char *s, char c) {
    return s && *s == c ? s + 1 : NULL;
}

int ztnx_parse_ipv4(const char *s, uint16_t port, ZtnxAddr *out) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    s = parse_uint(s, 3, &a);
    s = s ? parse_uint(expect(s, '.') ? s + 1 : "", 3, &b) : NULL;
    s = s ? parse_uint(expect(s, '.') ? s + 1 : "", 3, &c) : NULL;
    s = s ? parse_uint(expect(s, '.') ? s + 1 : "", 3, &d) : NULL;
    if (!s || *s || a > 255 || b > 255 || c > 255 || d > 255) return -1;
    memset(out, 0, sizeof *out);
    out->family = 4;
    out->ip[0] = (uint8_t)a;
    out->ip[1] = (uint8_t)b;
    out->ip[2] = (uint8_t)c;
    out->ip[3] = (uint8_t)d;
    out->port = port;
    return 0;
}

static const char kPayload[] = "zerotier-nx echo test";
#define ECHO_TIMEOUT_NS (30ull * 1000000000ull)

void ztnx_echo_init(ZtnxEcho *t, const ZtnxAddr *target) {
    memset(t, 0, sizeof *t);
    t->target = *target;
    t->tcp = t->udp = -1;
}

int ztnx_echo_step(ZtnxEcho *t, ZtnxEngine *e, uint64_t now_ns) {
    if (t->result) return t->result;
    if (!t->started_ns) {
        t->started_ns = now_ns;
        t->tcp = ztnx_net_tcp_connect(e, &t->target);
        t->udp = ztnx_net_udp_bind(e, 0);
    }
    const size_t plen = sizeof kPayload - 1;
    if (t->tcp > 0) {
        if (!t->tcp_sent && (ztnx_net_readiness(e, t->tcp) & ZTNX_WRITABLE))
            t->tcp_sent = ztnx_net_send(e, t->tcp, (const uint8_t *)kPayload, plen) == (int32_t)plen;
        int32_t n = ztnx_net_recv(e, t->tcp, (uint8_t *)t->tcp_got + t->tcp_got_len,
                                  sizeof t->tcp_got - 1 - t->tcp_got_len);
        if (n > 0) t->tcp_got_len += (size_t)n;
    }
    if (t->udp > 0 && !t->udp_ok) {
        if (now_ns - t->last_udp_ns > 1000000000ull) {
            ztnx_net_udp_sendto(e, t->udp, (const uint8_t *)kPayload, plen, &t->target);
            t->last_udp_ns = now_ns;
        }
        uint8_t buf[64];
        ZtnxAddr from;
        int32_t n = ztnx_net_udp_recvfrom(e, t->udp, buf, sizeof buf, &from);
        t->udp_ok = n == (int32_t)plen && !memcmp(buf, kPayload, plen);
    }
    int tcp_ok = t->tcp_got_len == plen && !memcmp(t->tcp_got, kPayload, plen);
    if (tcp_ok && t->udp_ok) {
        t->result = 1;
    } else if (now_ns - t->started_ns > ECHO_TIMEOUT_NS) {
        t->result = -1;
    }
    if (t->result) {
        if (t->tcp > 0) ztnx_net_close(e, t->tcp);
        if (t->udp > 0) ztnx_net_close(e, t->udp);
    }
    return t->result;
}

// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

uint64_t ztnx_parse_http_date(const char *s) {
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    // "Sun, 04 Oct 2026 01:23:45 GMT"
    char mon[4] = {0};
    unsigned d = 0, y = 0, hh = 0, mm = 0, ss = 0;
    if (strlen(s) < 29 || s[3] != ',' || s[4] != ' ') return 0;
    s = parse_uint(s + 5, 2, &d);
    s = expect(s, ' ');
    if (!s) return 0;
    memcpy(mon, s, 3);
    s = expect(s + 3, ' ');
    s = s ? parse_uint(s, 4, &y) : NULL;
    s = s ? parse_uint(expect(s, ' ') ? s + 1 : "", 2, &hh) : NULL;
    s = s ? parse_uint(expect(s, ':') ? s + 1 : "", 2, &mm) : NULL;
    s = s ? parse_uint(expect(s, ':') ? s + 1 : "", 2, &ss) : NULL;
    if (!s || strncmp(s, " GMT", 4) != 0) return 0;
    const char *p = strstr(months, mon);
    if (!p || (p - months) % 3 || d < 1 || d > 31 || hh > 23 || mm > 59 || ss > 60) return 0;
    unsigned m = (unsigned)((p - months) / 3) + 1;
    int64_t days = days_from_civil(y, m, d);
    return days < 0 ? 0 : (uint64_t)days * 86400 + hh * 3600 + mm * 60 + ss;
}

static bool plausible(uint64_t t) {
    return t >= (uint64_t)ZTNX_BUILD_UNIX && t <= (uint64_t)ZTNX_BUILD_UNIX + ZTNX_CLOCK_MAX_AHEAD;
}

// HEAD / over plain HTTP; returns the Date header's time, or 0.
static uint64_t http_date(const char *host) {
    uint32_t ip;
    if (ztnx_resolve_ipv4(host, &ip) != 0) return 0;
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons(80);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    uint64_t t = 0;
    if (fd >= 0) {
        struct timeval tv = {5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *)&sin, sizeof sin) == 0) {
            char req[300];
            int n = snprintf(req, sizeof req, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
            char resp[2048];
            size_t got = 0;
            if (send(fd, req, (size_t)n, 0) == n) {
                ssize_t r;
                while (got < sizeof resp - 1 && (r = recv(fd, resp + got, sizeof resp - 1 - got, 0)) > 0) got += (size_t)r;
            }
            resp[got] = 0;
            for (char *line = resp; line && *line; line = strstr(line, "\r\n") ? strstr(line, "\r\n") + 2 : NULL) {
                if (!strncasecmp(line, "Date:", 5)) {
                    t = ztnx_parse_http_date(line + 5 + strspn(line + 5, " "));
                    break;
                }
            }
        }
        close(fd);
    }
    return t;
}

uint64_t ztnx_sane_unix_time(uint64_t system_unix, const char *host, bool *corrected) {
    *corrected = false;
    if (plausible(system_unix)) return system_unix;
    uint64_t net = http_date(host);
    if (!plausible(net)) return 0;
    *corrected = true;
    return net;
}
