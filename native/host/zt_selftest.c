// Runs the ZeroTier glue's exceptions self-test on a host build.
#include <stdio.h>

#include "ztnx_engine.h"

int main(void) {
    const uint32_t failed = ztnx_engine_selftest();
    if (failed) {
        printf("zt-selftest: FAILED (0x%x)\n", failed);
        return 1;
    }
    printf("zt-selftest: ok\n");
    return 0;
}
