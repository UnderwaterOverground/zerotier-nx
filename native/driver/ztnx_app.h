// Shared application logic for ztnx front ends (host CLI, Switch app):
// the wall-clock check and the overlay echo self-test.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ztnx.h"

#ifdef __cplusplus
extern "C" {
#endif

// Fills buf with cryptographically secure random bytes (platform-provided).
void ztnx_platform_random(uint8_t *buf, size_t len);

// Wall clock sanity. Consoles often have wrong clocks (dead RTC battery, or
// Nintendo's NTP blocked by DNS filters), and TLS certificate checks need a
// roughly correct date.
//
// WireGuard needs it too: handshake timestamps must never go backwards.
//
// Returns `system_unix` if it is plausible: no earlier than the build date and
// no more than ZTNX_CLOCK_MAX_AHEAD after it. Otherwise asks `host` (e.g.
// ZTNX_UPDATE_HOST) for its HTTP Date header (plain HTTP, port 80) and uses
// that if it is plausible, setting *corrected. Returns 0 if neither is usable.
#define ZTNX_CLOCK_MAX_AHEAD (3ull * 365 * 86400)
uint64_t ztnx_sane_unix_time(uint64_t system_unix, const char *host, bool *corrected);

// Parses an RFC 7231 IMF-fixdate ("Fri, 02 Oct 2026 10:24:03 GMT"). 0 on error.
uint64_t ztnx_parse_http_date(const char *s);

// TCP + UDP echo against port 7 of a tunnel peer.
typedef struct {
    ZtnxAddr target;
    uint64_t started_ns, last_udp_ns;
    int32_t tcp, udp;
    bool tcp_sent;
    char tcp_got[64];
    size_t tcp_got_len;
    bool udp_ok;
    int result;  // 0 running, 1 passed, -1 failed
} ZtnxEcho;

// Parses "a.b.c.d" into an IPv4 ZtnxAddr. Returns 0 on success.
int ztnx_parse_ipv4(const char *s, uint16_t port, ZtnxAddr *out);
void ztnx_echo_init(ZtnxEcho *t, const ZtnxAddr *target);
// Advances the test; returns its result (0 while still running).
int ztnx_echo_step(ZtnxEcho *t, ZtnxEngine *e, uint64_t now_ns);

#ifdef __cplusplus
}
#endif
