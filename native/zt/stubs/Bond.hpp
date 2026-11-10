// Replacement for node/Bond.hpp: link bonding (multipath) is not wanted on the
// Switch, and the real header drags in osdep/Phy.hpp and osdep/Binder.hpp
// (sockets, ifaddrs, netlink). Peer, Node and IncomingPacket only need the
// controller to say "not in use" and a SharedPtr<Bond> that is always null.
#ifndef ZT_BOND_HPP
#define ZT_BOND_HPP

#include "AtomicCounter.hpp"
#include "Packet.hpp"
#include "Path.hpp"
#include "RuntimeEnvironment.hpp"
#include "SharedPtr.hpp"

#include <cstdint>

#define ZT_BOND_POLICY_NONE			 0
#define ZT_BOND_POLICY_ACTIVE_BACKUP 1
#define ZT_BOND_POLICY_BROADCAST	 2
#define ZT_BOND_POLICY_BALANCE_RR	 3
#define ZT_BOND_POLICY_BALANCE_XOR	 4
#define ZT_BOND_POLICY_BALANCE_AWARE 5

namespace ZeroTier {

class Peer;

class Bond {
	friend class SharedPtr<Bond>;

  public:
	Bond(const RuntimeEnvironment*) {}

	static inline int minReqMonitorInterval() { return 0; }
	static inline bool inUse() { return false; }
	static inline SharedPtr<Bond> createBond(const RuntimeEnvironment*, const SharedPtr<Peer>&) { return SharedPtr<Bond>(); }
	static inline void destroyBond(uint64_t) {}
	static inline void processBackgroundTasks(void*, int64_t) {}

	inline bool isReady() { return false; }
	inline void nominatePathToBond(const SharedPtr<Path>&, int64_t) {}
	inline void recordIncomingInvalidPacket(const SharedPtr<Path>&) {}
	inline void recordOutgoingPacket(const SharedPtr<Path>&, uint64_t, uint16_t, Packet::Verb, int32_t, int64_t) {}
	inline void receivedQoS(const SharedPtr<Path>&, int64_t, int, uint64_t*, uint16_t*) {}
	inline void recordIncomingPacket(const SharedPtr<Path>&, uint64_t, uint16_t, Packet::Verb, int32_t, int64_t) {}
	inline SharedPtr<Path> getAppropriatePath(int64_t, int32_t) { return SharedPtr<Path>(); }
	inline void processIncomingPathNegotiationRequest(uint64_t, SharedPtr<Path>&, int16_t) {}
	inline bool rateGateQoS(int64_t, SharedPtr<Path>&) { return false; }
	inline bool rateGatePathNegotiation(int64_t, SharedPtr<Path>&) { return false; }
	inline bool flowHashingSupported() { return false; }
	inline uint8_t policy() { return 0; }
	inline uint8_t getNumAliveLinks() { return 0; }
	inline uint8_t getNumTotalLinks() { return 0; }

  private:
	AtomicCounter __refCount;
};

}	// namespace ZeroTier
#endif
