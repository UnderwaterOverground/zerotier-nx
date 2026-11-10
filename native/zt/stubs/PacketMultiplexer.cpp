#include "Node.hpp"

namespace ZeroTier {

void PacketMultiplexer::putFrame(void* tPtr, uint64_t nwid, void** nuptr, const MAC& source, const MAC& dest, unsigned int etherType, unsigned int vlanId, const void* data, unsigned int len, unsigned int)
{
	RR->node->putFrame(tPtr, nwid, nuptr, source, dest, etherType, vlanId, data, len);
}

}	// namespace ZeroTier
