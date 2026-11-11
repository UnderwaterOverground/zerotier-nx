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
	// Hex by hand: the only formatted printing the core would otherwise do
	// on the Switch, where it brings in the C library's whole printf.
	static inline std::string hexStr(uint64_t v, int digits)
	{
		char buf[17];
		for (int i = digits - 1; i >= 0; --i) {
			buf[i] = "0123456789abcdef"[v & 0xf];
			v >>= 4;
		}
		buf[digits] = 0;
		return std::string(buf);
	}
	static inline std::string networkIDStr(uint64_t nwid)
	{
		return hexStr(nwid, 16);
	}
	static inline std::string nodeIDStr(uint64_t addr)
	{
		return hexStr(addr, 10);
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
