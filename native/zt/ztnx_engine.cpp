// The ZeroTier core behind a small C ABI. See ztnx_engine.h for the rules.
#include "ztnx_engine.h"

#include <ZeroTierOne.h>

#include <new>
#include <stdexcept>

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

	return failed;
}
