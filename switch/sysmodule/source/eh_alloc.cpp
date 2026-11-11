// Storage for thrown C++ exceptions, in place of libstdc++'s (eh_alloc.cc).
// That one takes a 72 KB emergency pool from the heap when the process
// starts, for exceptions thrown when malloc fails. ZeroTier's core throws
// small things (an int, std::bad_alloc, std::out_of_range) and only on the
// engine thread, so a few static slots do: defining these two functions
// keeps libstdc++'s object, and its pool, out of the link.
//
// The boot self-test (ztnx_engine_selftest) throws and catches through
// this before anything else runs.
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <exception>

namespace {

    // sizeof(__cxa_refcounted_exception) on AArch64 (libstdc++'s
    // unwind-cxx.h): __cxa_throw expects that header right below the thrown
    // object. Checked against the toolchain's own __cxa_allocate_exception,
    // which adds the same 0x80 (devkitA64, GCC 15.2).
    constexpr size_t HeaderSize = 0x80;
    constexpr size_t SlotSize = HeaderSize + 64;
    constexpr int Slots = 4;

    alignas(16) constinit unsigned char g_slots[Slots][SlotSize] = {};
    constinit std::atomic<bool> g_slot_used[Slots] = {};

}

extern "C" void *__cxa_allocate_exception(size_t thrown_size) noexcept {
    const size_t size = thrown_size + HeaderSize;
    void *p = std::malloc(size);
    if (p == nullptr && size <= SlotSize) {
        for (int i = 0; i < Slots; i++) {
            if (!g_slot_used[i].exchange(true)) {
                p = g_slots[i];
                break;
            }
        }
    }
    if (p == nullptr) std::terminate();
    std::memset(p, 0, HeaderSize);
    return static_cast<unsigned char *>(p) + HeaderSize;
}

extern "C" void __cxa_free_exception(void *thrown) noexcept {
    unsigned char *p = static_cast<unsigned char *>(thrown) - HeaderSize;
    for (int i = 0; i < Slots; i++) {
        if (p == g_slots[i]) {
            g_slot_used[i] = false;
            return;
        }
    }
    std::free(p);
}
