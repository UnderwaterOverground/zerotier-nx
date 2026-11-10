// The ZeroTier core behind a small C ABI (see ztnx_engine.cpp).
//
// Everything here is for the engine thread only, with no runtime lock held:
// the core's call paths need far more stack than a bsd:u MITM thread has
// (Multicaster::send alone has a 64 KB frame), and its callbacks must never
// call back into it.
#ifndef ZTNX_ENGINE_H
#define ZTNX_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Provided by the platform where there is no /dev/urandom (the sysmodule):
// cryptographically secure random bytes. Must not fail.
void ztnx_secure_random(void *buf, unsigned int len);

// Checks that C++ exceptions work in this binary: a throw and catch, unwinding
// through a destructor, std::bad_alloc from operator new, and a throw inside
// the core itself (a node without an identity). The core relies on all four;
// Atmosphère's default link turns them into aborts. Returns 0 if all passed,
// else one bit per failed check (1, 2, 4, 8).
uint32_t ztnx_engine_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
