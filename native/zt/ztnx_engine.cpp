// The ZeroTier core behind a small C ABI. See ztnx_engine.h for the rules.
#include "ztnx_engine.h"

#include <ZeroTierOne.h>

#include "Address.hpp"
#include "Identity.hpp"
#include "MAC.hpp"
#include "Node.hpp"

#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>

#include <netinet/in.h>
#include <sys/socket.h>

// ---- the node ---------------------------------------------------------------

namespace {

// Frames from the network wait here until the caller takes them. Sized for a
// read batch of datagrams (16) carrying full packets, twice over.
constexpr size_t kArenaBytes = 48 * 1024;
constexpr size_t kArenaFrames = 64;
constexpr unsigned kEvents = 8;
// The one UDP socket, as ZeroTier names it (any nonzero value).
constexpr int64_t kLocalSocket = 1;
constexpr uint64_t kBroadcastMac = 0xffffffffffffULL;

}	// namespace

struct ZtnxEngine {
	ZT_Node* node;
	ZtnxEngineHooks hooks;
	volatile int64_t deadline;
	uint64_t address;
	uint64_t nwid;	 // 0 until joined

	ZtnxFrame frames[kArenaFrames];
	size_t frameCount;
	size_t arenaUsed;
	uint32_t framesDropped;

	bool configChanged;
	ZtnxNetConfig config;

	uint32_t events[kEvents];
	unsigned eventHead, eventCount;

	uint32_t subscribed[ZTNX_MAX_ADDRS];   // IPv4 addresses, host order
	size_t subscribedCount;

	uint8_t arena[kArenaBytes];
};

namespace {

inline ZtnxEngine* self(void* uptr)
{
	return static_cast<ZtnxEngine*>(uptr);
}

// Which state objects are kept. The peer cache would mean an SD card read for
// every address ZeroTier hears of and a write per peer when it shuts down;
// moons are not used.
bool keptState(enum ZT_StateObjectType type)
{
	switch (type) {
		case ZT_STATE_OBJECT_IDENTITY_PUBLIC:
		case ZT_STATE_OBJECT_IDENTITY_SECRET:
		case ZT_STATE_OBJECT_PLANET:
		case ZT_STATE_OBJECT_NETWORK_CONFIG:
			return true;
		default:
			return false;
	}
}

void onStatePut(ZT_Node*, void* uptr, void*, enum ZT_StateObjectType type, const uint64_t id[2], const void* data, int len)
{
	ZtnxEngine* e = self(uptr);
	if (keptState(type) && e->hooks.state_put) {
		e->hooks.state_put(e->hooks.ctx, (int)type, id[0], data, len);
	}
}

int onStateGet(ZT_Node*, void* uptr, void*, enum ZT_StateObjectType type, const uint64_t id[2], void* buf, unsigned int cap)
{
	ZtnxEngine* e = self(uptr);
	if (! keptState(type) || ! e->hooks.state_get) {
		return -1;
	}
	return e->hooks.state_get(e->hooks.ctx, (int)type, id[0], buf, cap);
}

int onWireSend(ZT_Node*, void* uptr, void*, int64_t, const struct sockaddr_storage* to, const void* data, unsigned int len, unsigned int ttl)
{
	ZtnxEngine* e = self(uptr);
	if (to->ss_family != AF_INET || ! e->hooks.wire_send) {
		return -1;
	}
	const struct sockaddr_in* in = reinterpret_cast<const struct sockaddr_in*>(to);
	return e->hooks.wire_send(e->hooks.ctx, in->sin_addr.s_addr, ntohs(in->sin_port), data, len, ttl);
}

void onFrame(ZT_Node*, void* uptr, void*, uint64_t nwid, void**, uint64_t srcMac, uint64_t dstMac, unsigned int etherType, unsigned int, const void* data, unsigned int len)
{
	ZtnxEngine* e = self(uptr);
	if (nwid != e->nwid) {
		return;
	}
	if (e->frameCount >= kArenaFrames || len > kArenaBytes - e->arenaUsed) {
		++e->framesDropped;
		return;
	}
	uint8_t* at = e->arena + e->arenaUsed;
	memcpy(at, data, len);
	ZtnxFrame& f = e->frames[e->frameCount++];
	f.src_mac = srcMac;
	f.dst_mac = dstMac;
	f.ethertype = etherType;
	f.len = len;
	f.data = at;
	e->arenaUsed += len;
}

// The prefix length ZeroTier keeps in an address's port field.
uint8_t prefixOf(const struct sockaddr_in* in)
{
	const unsigned bits = ntohs(in->sin_port);
	return (uint8_t)(bits > 32 ? 32 : bits);
}

// ZT_VirtualNetworkConfig is tens of kilobytes: it is read in place here and
// never copied.
int onConfig(ZT_Node*, void* uptr, void*, uint64_t nwid, void**, enum ZT_VirtualNetworkConfigOperation op, const ZT_VirtualNetworkConfig* zc)
{
	ZtnxEngine* e = self(uptr);
	if (nwid != e->nwid) {
		return 0;
	}
	ZtnxNetConfig& c = e->config;
	memset(&c, 0, sizeof(c));
	c.nwid = nwid;
	e->configChanged = true;
	if (op == ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_DOWN || op == ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_DESTROY || ! zc) {
		c.status = ZTNX_NET_DOWN;
		return 0;
	}
	c.mac = zc->mac;
	c.status = (uint32_t)zc->status;
	c.truncated = zc->truncated;
	c.revision = (uint32_t)zc->netconfRevision;
	c.mtu = (uint16_t)(zc->mtu > 0xffff ? 0xffff : zc->mtu);
	c.broadcast = zc->broadcastEnabled ? 1 : 0;
	c.is_private = (zc->type == ZT_NETWORK_TYPE_PRIVATE) ? 1 : 0;
	memcpy(c.name, zc->name, sizeof(c.name) - 1);
	for (unsigned int i = 0; i < zc->assignedAddressCount && c.n_addrs < ZTNX_MAX_ADDRS; ++i) {
		if (zc->assignedAddresses[i].ss_family != AF_INET) {
			continue;
		}
		const struct sockaddr_in* in = reinterpret_cast<const struct sockaddr_in*>(&zc->assignedAddresses[i]);
		ZtnxV4Net& a = c.addrs[c.n_addrs++];
		memcpy(a.ip, &in->sin_addr.s_addr, 4);
		a.prefix = prefixOf(in);
	}
	for (unsigned int i = 0; i < zc->routeCount && c.n_routes < ZTNX_MAX_ROUTES; ++i) {
		if (zc->routes[i].target.ss_family != AF_INET) {
			continue;
		}
		const struct sockaddr_in* target = reinterpret_cast<const struct sockaddr_in*>(&zc->routes[i].target);
		ZtnxV4Route& r = c.routes[c.n_routes++];
		memcpy(r.target, &target->sin_addr.s_addr, 4);
		r.prefix = prefixOf(target);
		if (zc->routes[i].via.ss_family == AF_INET) {
			const struct sockaddr_in* via = reinterpret_cast<const struct sockaddr_in*>(&zc->routes[i].via);
			if (via->sin_addr.s_addr != 0) {
				r.has_via = 1;
				memcpy(r.via, &via->sin_addr.s_addr, 4);
			}
		}
	}
	return 0;
}

void pushEvent(ZtnxEngine* e, uint32_t kind)
{
	if (e->eventCount == kEvents) {	  // full: the oldest goes
		e->eventHead = (e->eventHead + 1) % kEvents;
		--e->eventCount;
	}
	e->events[(e->eventHead + e->eventCount) % kEvents] = kind;
	++e->eventCount;
}

void onEvent(ZT_Node*, void* uptr, void*, enum ZT_Event event, const void*)
{
	ZtnxEngine* e = self(uptr);
	switch (event) {
		case ZT_EVENT_ONLINE:
			pushEvent(e, ZTNX_EVENT_ONLINE);
			break;
		case ZT_EVENT_OFFLINE:
			pushEvent(e, ZTNX_EVENT_OFFLINE);
			break;
		case ZT_EVENT_FATAL_ERROR_IDENTITY_COLLISION:
			pushEvent(e, ZTNX_EVENT_IDENTITY_COLLISION);
			break;
		default:
			break;
	}
}

void toStorage(struct sockaddr_storage* ss, uint32_t ipBe, uint16_t port)
{
	memset(ss, 0, sizeof(*ss));
	struct sockaddr_in* in = reinterpret_cast<struct sockaddr_in*>(ss);
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = ipBe;
	in->sin_port = htons(port);
}

}	// namespace

extern "C" ZtnxEngine* ztnx_engine_new(const ZtnxEngineHooks* hooks, int64_t now_ms, int* rc)
{
	int unused;
	if (! rc) {
		rc = &unused;
	}
	ZtnxEngine* e = static_cast<ZtnxEngine*>(calloc(1, sizeof(ZtnxEngine)));
	if (! e) {
		*rc = ZTNX_ENGINE_OUT_OF_MEMORY;
		return nullptr;
	}
	e->hooks = *hooks;
	e->deadline = now_ms;

	struct ZT_Node_Callbacks cb;
	memset(&cb, 0, sizeof(cb));
	cb.statePutFunction = onStatePut;
	cb.stateGetFunction = onStateGet;
	cb.wirePacketSendFunction = onWireSend;
	cb.virtualNetworkFrameFunction = onFrame;
	cb.virtualNetworkConfigFunction = onConfig;
	cb.eventCallback = onEvent;
	struct ZT_Node_Config config;
	memset(&config, 0, sizeof(config));
	*rc = (int)ZT_Node_new(&e->node, &config, e, nullptr, &cb, now_ms);
	if (*rc != ZT_RESULT_OK || ! e->node) {
		free(e);
		return nullptr;
	}
	e->address = ZT_Node_address(e->node);
	return e;
}

extern "C" void ztnx_engine_free(ZtnxEngine* e)
{
	if (! e) {
		return;
	}
	if (e->nwid) {
		ZT_Node_leave(e->node, e->nwid, nullptr, nullptr);
	}
	ZT_Node_delete(e->node);
	free(e);
}

extern "C" uint64_t ztnx_engine_address(const ZtnxEngine* e)
{
	return e->address;
}

extern "C" int ztnx_engine_leave(ZtnxEngine* e)
{
	if (! e->nwid) {
		return 0;
	}
	// The callbacks this makes (DOWN, DESTROY) are for the network being left.
	const int rc = (int)ZT_Node_leave(e->node, e->nwid, nullptr, nullptr);
	e->nwid = 0;
	e->subscribedCount = 0;
	return rc;
}

extern "C" int ztnx_engine_join(ZtnxEngine* e, uint64_t nwid)
{
	if (e->nwid == nwid) {
		return 0;
	}
	ztnx_engine_leave(e);
	e->nwid = nwid;
	memset(&e->config, 0, sizeof(e->config));
	e->config.nwid = nwid;
	e->config.status = ZTNX_NET_REQUESTING;
	e->configChanged = true;
	const int rc = (int)ZT_Node_join(e->node, nwid, nullptr, nullptr);
	if (rc != ZT_RESULT_OK) {
		e->nwid = 0;
	}
	return rc;
}

extern "C" void ztnx_engine_wire_in(ZtnxEngine* e, uint32_t ip_be, uint16_t port, const void* data, unsigned int len, int64_t now_ms)
{
	struct sockaddr_storage from;
	toStorage(&from, ip_be, port);
	ZT_Node_processWirePacket(e->node, nullptr, now_ms, kLocalSocket, &from, data, len, &e->deadline);
}

extern "C" void ztnx_engine_frame_out(ZtnxEngine* e, uint64_t dst_mac, unsigned int ethertype, const void* data, unsigned int len, int64_t now_ms)
{
	if (! e->nwid || e->config.status != ZTNX_NET_OK) {
		return;
	}
	ZT_Node_processVirtualNetworkFrame(e->node, nullptr, now_ms, e->nwid, e->config.mac, dst_mac, ethertype, 0, data, len, &e->deadline);
}

extern "C" void ztnx_engine_background(ZtnxEngine* e, int64_t now_ms)
{
	ZT_Node_processBackgroundTasks(e->node, nullptr, now_ms, &e->deadline);
}

extern "C" int64_t ztnx_engine_deadline_ms(const ZtnxEngine* e)
{
	return e->deadline;
}

extern "C" void ztnx_engine_network_up(ZtnxEngine* e, uint32_t local_ip_be, uint16_t port, int64_t now_ms)
{
	ZT_Node_clearLocalInterfaceAddresses(e->node);
	if (local_ip_be) {
		struct sockaddr_storage local;
		toStorage(&local, local_ip_be, port);
		ZT_Node_addLocalInterfaceAddress(e->node, &local);
	}
	e->deadline = now_ms;
}

extern "C" size_t ztnx_engine_frames(ZtnxEngine* e, const ZtnxFrame** out)
{
	*out = e->frames;
	return e->frameCount;
}

extern "C" void ztnx_engine_frames_done(ZtnxEngine* e)
{
	e->frameCount = 0;
	e->arenaUsed = 0;
}

extern "C" bool ztnx_engine_frames_high(const ZtnxEngine* e)
{
	return e->arenaUsed > kArenaBytes / 2 || e->frameCount > kArenaFrames / 2;
}

extern "C" bool ztnx_engine_take_config(ZtnxEngine* e, ZtnxNetConfig* out)
{
	if (! e->configChanged) {
		return false;
	}
	e->configChanged = false;
	*out = e->config;
	return true;
}

extern "C" uint32_t ztnx_engine_take_event(ZtnxEngine* e)
{
	if (! e->eventCount) {
		return 0;
	}
	const uint32_t kind = e->events[e->eventHead];
	e->eventHead = (e->eventHead + 1) % kEvents;
	--e->eventCount;
	return kind;
}

extern "C" void ztnx_engine_multicast_sync(ZtnxEngine* e, const uint32_t* ipv4_be, size_t n)
{
	if (! e->nwid) {
		return;
	}
	if (n > ZTNX_MAX_ADDRS) {
		n = ZTNX_MAX_ADDRS;
	}
	uint32_t wanted[ZTNX_MAX_ADDRS];
	for (size_t i = 0; i < n; ++i) {
		wanted[i] = ntohl(ipv4_be[i]);
	}
	// ARP for an IPv4 address travels as the broadcast MAC with the address
	// as the group's ADI (MulticastGroup::deriveMulticastGroupForAddressResolution).
	for (size_t i = 0; i < e->subscribedCount; ++i) {
		bool keep = false;
		for (size_t j = 0; j < n; ++j) {
			keep = keep || (wanted[j] == e->subscribed[i]);
		}
		if (! keep) {
			ZT_Node_multicastUnsubscribe(e->node, e->nwid, kBroadcastMac, e->subscribed[i]);
		}
	}
	for (size_t j = 0; j < n; ++j) {
		bool have = false;
		for (size_t i = 0; i < e->subscribedCount; ++i) {
			have = have || (wanted[j] == e->subscribed[i]);
		}
		if (! have) {
			ZT_Node_multicastSubscribe(e->node, nullptr, e->nwid, kBroadcastMac, wanted[j]);
		}
	}
	memcpy(e->subscribed, wanted, n * sizeof(uint32_t));
	e->subscribedCount = n;
}

extern "C" size_t ztnx_engine_peers(ZtnxEngine* e, ZtnxPeerInfo* out, size_t max, int64_t now_ms)
{
	// Not ZT_Node_peers: that allocates about 4 KB per peer for its answer.
	ZeroTier::Node::PeerSummary peers[ZTNX_ENGINE_PEERS_MAX];
	if (max > ZTNX_ENGINE_PEERS_MAX) {
		max = ZTNX_ENGINE_PEERS_MAX;
	}
	const size_t total = reinterpret_cast<ZeroTier::Node*>(e->node)->peerSummaries(peers, (unsigned long)max);
	for (size_t i = 0; i < total && i < max; ++i) {
		const ZeroTier::Node::PeerSummary& p = peers[i];
		ZtnxPeerInfo& o = out[i];
		memset(&o, 0, sizeof(o));
		o.address = p.address;
		o.latency_ms = p.latency;
		o.role = p.role;
		if (p.versionMajor >= 0) {
			o.version[0] = (uint8_t)p.versionMajor;
			o.version[1] = (uint8_t)p.versionMinor;
			o.version[2] = (uint8_t)p.versionRev;
		}
		if (p.ip4) {
			o.direct = 1;
			memcpy(o.path_ip, &p.ip4, 4);
			o.path_port = p.port;
			const int64_t ago = now_ms - p.lastReceive;
			o.last_rx_ms = (uint32_t)(ago < 0 ? 0 : (ago > 0xffffffffLL ? 0xffffffffLL : ago));
		}
	}
	return total;
}

extern "C" uint64_t ztnx_engine_generate_identity(void* scratch, char* secret, char* public_)
{
	try {
		ZeroTier::Identity id;
		id.generate(scratch);
		char buf[ZT_IDENTITY_STRING_BUFFER_LENGTH];
		static_assert(ZT_IDENTITY_STRING_BUFFER_LENGTH <= ZTNX_IDENTITY_TEXT_MAX, "identity text size");
		if (! id.toString(true, buf)) {
			return 0;
		}
		memcpy(secret, buf, strlen(buf) + 1);
		if (! id.toString(false, buf)) {
			return 0;
		}
		memcpy(public_, buf, strlen(buf) + 1);
		return id.address().toInt();
	}
	catch (...) {
		return 0;
	}
}

extern "C" uint64_t ztnx_engine_identity_address(const char* secret)
{
	try {
		ZeroTier::Identity id;
		if (! id.fromString(secret) || ! id.hasPrivate()) {
			return 0;
		}
		return id.address().toInt();
	}
	catch (...) {
		return 0;
	}
}

// ---- the exceptions self-test -----------------------------------------------

namespace {

struct Marker {
	uint32_t* seen;
	~Marker() { *seen |= 1; }
};

[[gnu::noinline]] void throwInt(int v)
{
	throw v;
}

[[gnu::noinline]] void throwThroughDestructor(uint32_t* seen)
{
	Marker m { seen };
	throw std::runtime_error("ztnx");
}

// Not inlined, so the compiler cannot drop the allocation it is asked for.
[[gnu::noinline]] char* allocate(size_t bytes)
{
	return new char[bytes];
}

int noState(ZT_Node*, void*, void*, enum ZT_StateObjectType, const uint64_t[2], void*, unsigned int)
{
	return -1;
}
void dropState(ZT_Node*, void*, void*, enum ZT_StateObjectType, const uint64_t[2], const void*, int)
{
}
int dropWire(ZT_Node*, void*, void*, int64_t, const struct sockaddr_storage*, const void*, unsigned int, unsigned int)
{
	return -1;
}
void dropFrame(ZT_Node*, void*, void*, uint64_t, void**, uint64_t, uint64_t, unsigned int, unsigned int, const void*, unsigned int)
{
}
int ignoreConfig(ZT_Node*, void*, void*, uint64_t, void**, enum ZT_VirtualNetworkConfigOperation, const ZT_VirtualNetworkConfig*)
{
	return 0;
}
void ignoreEvent(ZT_Node*, void*, void*, enum ZT_Event, const void*)
{
}

}	// namespace

extern "C" uint64_t ztnx_engine_peer_mac(uint64_t address, uint64_t nwid)
{
	return ZeroTier::MAC(ZeroTier::Address(address), nwid).toInt();
}

extern "C" uint32_t ztnx_engine_selftest(void)
{
	uint32_t failed = 0;

	try {
		throwInt(42);
		failed |= 1;
	}
	catch (int v) {
		if (v != 42) {
			failed |= 1;
		}
	}
	catch (...) {
		failed |= 1;
	}

	uint32_t seen = 0;
	try {
		throwThroughDestructor(&seen);
		failed |= 2;
	}
	catch (const std::exception&) {
		if (! seen) {
			failed |= 2;
		}
	}
	catch (...) {
		failed |= 2;
	}

	try {
		delete[] allocate((~(size_t)0) / 2);
		failed |= 4;
	}
	catch (const std::bad_alloc&) {
	}
	catch (...) {
		failed |= 4;
	}

	// With no stored identity the node's constructor throws (it must not make
	// one itself: patches/zerotier-0007), and ZT_Node_new turns that into an
	// error code.
	struct ZT_Node_Callbacks cb = {};
	cb.statePutFunction = dropState;
	cb.stateGetFunction = noState;
	cb.wirePacketSendFunction = dropWire;
	cb.virtualNetworkFrameFunction = dropFrame;
	cb.virtualNetworkConfigFunction = ignoreConfig;
	cb.eventCallback = ignoreEvent;
	struct ZT_Node_Config config = {};
	ZT_Node* node = nullptr;
	const enum ZT_ResultCode rc = ZT_Node_new(&node, &config, nullptr, nullptr, &cb, 1700000000000LL);
	if ((rc != ZT_RESULT_FATAL_ERROR_INTERNAL) || node) {
		failed |= 8;
		if (node) {
			ZT_Node_delete(node);
		}
	}

	// A signature made with an identity from stock ZeroTier must verify
	// against the public key stock ZeroTier computed for it. Signing
	// multiplies the curve's base point, which this build does without the
	// usual table (patches/zerotier-0010); so does making an identity.
	try {
		// A throwaway made with zerotier-idtool for this test, used nowhere.
		static const char kTestIdentity[] =
			"900bc5c5c0:0:69e9037cb0f3efe92b20932bbddc2012b173f4127af3ebb4e199c41bdf8a2d1ff2d46a58a1aadcbd8a69e7ce4abdb2e2a3ec883c7b831bfee327080758"
			"bd3ab3:31619d0c2c366ea02b00c153bf23756f427095f33284e4d1c971d7a2a128d5f5b11d8dbe875687852c3bc98e0d2480379dcbc822e64832b241e2b462f6c0e95f";
		static const char kMessage[] = "zerotier-nx self-test";
		const ZeroTier::Identity id(kTestIdentity);
		ZeroTier::ECC::Signature sig = id.sign(kMessage, sizeof(kMessage));
		if (! id.verify(kMessage, sizeof(kMessage), sig)) {
			failed |= 16;
		}
		sig.data[7] ^= 1;
		if (id.verify(kMessage, sizeof(kMessage), sig)) {
			failed |= 16;
		}
	}
	catch (...) {
		failed |= 16;
	}

	return failed;
}
