// Replacement for node/PacketMultiplexer.hpp: the real one hands decoded frames
// to std::thread workers. Here putFrame goes straight to Node::putFrame, which
// is what upstream does too when the multiplexer is disabled.
#ifndef ZT_PACKET_MULTIPLEXER_HPP
#define ZT_PACKET_MULTIPLEXER_HPP

#include "MAC.hpp"
#include "RuntimeEnvironment.hpp"

namespace ZeroTier {

class PacketMultiplexer {
  public:
	const RuntimeEnvironment* RR;
	PacketMultiplexer(const RuntimeEnvironment* renv) : RR(renv) {}
	void setUpPostDecodeReceiveThreads(unsigned int, bool) {}
	void putFrame(void* tPtr, uint64_t nwid, void** nuptr, const MAC& source, const MAC& dest, unsigned int etherType, unsigned int vlanId, const void* data, unsigned int len, unsigned int flowId);
};

}	// namespace ZeroTier
#endif
