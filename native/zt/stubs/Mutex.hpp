// Replacement for node/Mutex.hpp on the Switch toolchain (no pthreads).
// Uses libnx's kernel mutex, which is what a real port would do.
#ifndef ZT_MUTEX_HPP
#define ZT_MUTEX_HPP

extern "C" {
#include <switch/kernel/mutex.h>
}

namespace ZeroTier {

class Mutex {
  public:
	Mutex() { mutexInit(&_m); }
	inline void lock() const { mutexLock(const_cast<::Mutex*>(&_m)); }
	inline void unlock() const { mutexUnlock(const_cast<::Mutex*>(&_m)); }
	class Lock {
	  public:
		Lock(Mutex& m) : _m(&m) { m.lock(); }
		Lock(const Mutex& m) : _m(const_cast<Mutex*>(&m)) { _m->lock(); }
		~Lock() { _m->unlock(); }
	  private:
		Mutex* const _m;
	};

  private:
	Mutex(const Mutex&) {}
	const Mutex& operator=(const Mutex&) { return *this; }
	::Mutex _m;
};

}	// namespace ZeroTier
#endif
