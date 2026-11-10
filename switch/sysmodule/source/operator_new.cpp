// operator new and delete on malloc (the fixed heap in main.cpp).
//
// This file alone is compiled with C++ exceptions (see the Makefile), so that
// a failed allocation throws std::bad_alloc. ZeroTier's core catches it and
// drops the packet it was handling. Everything else here is built without
// exceptions or unwind tables, so a failed `new` there ends in
// std::terminate, as an abort did before.
#include <cstdlib>
#include <new>

void *operator new(size_t size) {
    if (void *p = std::malloc(size)) {
        return p;
    }
    throw std::bad_alloc();
}
void *operator new[](size_t size) { return operator new(size); }
void *operator new(size_t size, const std::nothrow_t &) noexcept { return std::malloc(size); }
void *operator new[](size_t size, const std::nothrow_t &) noexcept { return std::malloc(size); }
void operator delete(void *p) noexcept { std::free(p); }
void operator delete(void *p, size_t) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete[](void *p, size_t) noexcept { std::free(p); }
