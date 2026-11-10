// Replacement for osdep/OSUtils.hpp: only what node/ itself uses.
#ifndef ZT_OSUTILS_HPP
#define ZT_OSUTILS_HPP

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>

namespace ZeroTier {

class OSUtils {
  public:
	static inline std::string networkIDStr(uint64_t nwid)
	{
		char buf[24];
		snprintf(buf, sizeof(buf), "%.16llx", (unsigned long long)nwid);
		return std::string(buf);
	}
	static inline std::string nodeIDStr(uint64_t addr)
	{
		char buf[16];
		snprintf(buf, sizeof(buf), "%.10llx", (unsigned long long)addr);
		return std::string(buf);
	}
	static inline int ztsnprintf(char* buf, unsigned int len, const char* fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		int n = vsnprintf(buf, len, fmt, ap);
		va_end(ap);
		if (n < 0 || (unsigned int)n >= len) {
			if (len)
				buf[len - 1] = 0;
			return (int)len - 1;
		}
		return n;
	}
};

}	// namespace ZeroTier
#endif
