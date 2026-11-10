// Checks GitHub for a newer zerotier-nx release: one HTTPS request for
// github.com/<repo>/releases/latest, whose redirect names the latest tag.
// Non-blocking after the start: call ztnx_update_step until it returns
// something other than ZTNX_UPDATE_PENDING, then ztnx_update_free.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Where releases are published.
#define ZTNX_UPDATE_HOST "github.com"
#define ZTNX_UPDATE_REPO "UnderwaterOverground/zerotier-nx"

typedef struct ZtnxUpdate ZtnxUpdate;

enum {
    ZTNX_UPDATE_FAILED = -1,  // ztnx_update_error says why
    ZTNX_UPDATE_PENDING = 0,
    ZTNX_UPDATE_CURRENT = 1,  // no newer release
    ZTNX_UPDATE_NEWER = 2,    // ztnx_update_latest has its version
};

// Resolves github.com (blocking, like the driver's connects) and starts
// connecting. `current` is our version ("1.0.1"). The check gives up
// `timeout_ms` after now_ns. NULL only if out of memory.
ZtnxUpdate *ztnx_update_start(const char *repo, const char *current, uint64_t now_ns, uint32_t timeout_ms);
int ztnx_update_step(ZtnxUpdate *u, uint64_t now_ns);
// The latest release's version without the "v" ("1.1.0"), or "" if unknown.
const char *ztnx_update_latest(const ZtnxUpdate *u);
const char *ztnx_update_error(const ZtnxUpdate *u);
// Closes the connection.
void ztnx_update_free(ZtnxUpdate *u);

// Compares dotted versions numerically ("1.10.0" > "1.9.2"); anything after
// the numbers ("-beta") is ignored. Returns <0, 0 or >0.
int ztnx_version_compare(const char *a, const char *b);

#ifdef __cplusplus
}
#endif
