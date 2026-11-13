# ZeroTier's core (third_party/ZeroTierOne/node, patched by patches/zerotier-*)
# and the glue around it, as one static library.
#
#   make -C native/zt PLATFORM=switch    inside the ztnx-build image
#   make -C native/zt PLATFORM=host      Linux or macOS, for tests and e2e
#
# Output: $(OUT)/libztcore.a. The core is compiled with C++ exceptions, which
# it needs; nothing else in the sysmodule is.
PLATFORM ?= host
ZT  ?= ../../third_party/ZeroTierOne
OUT ?= ../../target/zt-$(PLATFORM)

# The Switch's limits. Hosts build with the same ones, so tests see the same
# sizes and the same truncation. A network that needs more than these gets the
# "config too large" flag (patches/zerotier-0006).
LIMITS := -DZT_RX_QUEUE_SIZE=4 -DZT_MAX_NETWORK_RULES=64 -DZT_MAX_NETWORK_SPECIALISTS=16 \
          -DZT_MAX_NETWORK_ROUTES=16 -DZT_MAX_NETWORK_CAPABILITIES=2 -DZT_MAX_NETWORK_TAGS=8 \
          -DZT_MAX_MULTICAST_SUBSCRIPTIONS=64 -DZT_EXPECTING_REPLIES_BUCKET_MASK1=31 \
          -DZT_COMPACT_OUTBOUND_MULTICAST -DZT_MULTICAST_TX_QUEUE_SIZE=4 \
          -DZT_MAX_ZT_ASSIGNED_ADDRESSES=8 -DZT_NETWORK_MAX_INCOMING_UPDATES=1 \
          -DZT_MAX_PEER_NETWORK_PATHS=4 -DZT_RX_FRAGMENT_MAX=1500 \
          -DZT_SECURE_RANDOM_BUFFER_SIZE=1024 -DZT_NETWORKCONFIG_RESET_IN_PLACE -DZT_ED25519_NO_BASE_TABLE \
          -DZT_NO_SEND_COMPRESSION -DZT_MULTICAST_SEND_STACK_INDEXES=128 \
          -DZT_NO_LOCAL_IDENTITY_VALIDATION -DZT_NO_THREADS -DZT_LEAF_ONLY \
          -DZT_MAX_PEERS=48 -DZT_MAX_PATHS=128 -DZT_SELFAWARENESS_MAX_ENTRIES=32

# Not built: x86 AES, metrics, bonding, the threaded multiplexer and remote
# tracing. Metrics, bonding and the multiplexer are replaced by the headers in
# stubs/, force-included so that the real headers' include guards are already
# taken; tracing by stubs/Trace.cpp, whose events do nothing.
NODE_SRCS := $(filter-out $(addprefix $(ZT)/node/,AES_aesni.cpp Metrics.cpp Bond.cpp PacketMultiplexer.cpp Trace.cpp),$(wildcard $(ZT)/node/*.cpp))
GLUE_SRCS := $(wildcard *.cpp) stubs/PacketMultiplexer.cpp stubs/Trace.cpp

COMMON := -MMD -MP -g -ffunction-sections -fdata-sections -fno-strict-aliasing -fwrapv -fexceptions \
          -std=gnu++17 -Wall -Wno-deprecated -Wno-unused-variable \
          -DNDEBUG -DZT_NO_PEER_METRICS $(LIMITS) \
          -I$(ZT)/node -I$(ZT)/include -I$(ZT) -isystem $(ZT)/ext -I. -I../../crates/ztnx-ffi/include
# In this order: the later stubs include core headers that need the mutex.
STUBS  := -include stubs/Metrics.hpp -include stubs/OSUtils.hpp -include stubs/Bond.hpp \
          -include stubs/PacketMultiplexer.hpp

ifeq ($(PLATFORM),switch)
  DEVKITPRO ?= /opt/devkitpro
  CXX := $(DEVKITPRO)/devkitA64/bin/aarch64-none-elf-g++
  AR  := $(DEVKITPRO)/devkitA64/bin/aarch64-none-elf-gcc-ar
  # Atmosphère's sysmodule flags (config/common.mk and stratosphere.mk) minus
  # -fno-exceptions. -Os: the core is 430 KB of the image.
  CXXFLAGS := $(COMMON) -include stubs/Mutex.hpp $(STUBS) \
              -march=armv8-a+crypto -mtune=cortex-a57 -mtp=soft -fPIE -Os -fno-rtti -flto \
              -D__SWITCH__ -DZT_NO_TYPE_PUNNING -DZT_ARCH_ARM_HAS_NEON \
              -DZT_SECURE_RANDOM_HOOK=ztnx_secure_random \
              -D_MT_ALLOCATOR_H -D_POOL_ALLOCATOR_H -D_EXTPTR_ALLOCATOR_H -D_DEBUG_ALLOCATOR_H \
              -I$(DEVKITPRO)/libnx/include -Istubs/sys-include \
              $(EXTRA_CXXFLAGS)
else
  CXX ?= c++
  AR  ?= ar
  # -fPIC: the library also goes into the LD_PRELOAD shim.
  CXXFLAGS := $(COMMON) $(STUBS) -O2 -fPIC -pthread $(EXTRA_CXXFLAGS)
  ifneq ($(filter aarch64 arm64,$(shell uname -m)),)
    CXXFLAGS += -DZT_NO_TYPE_PUNNING -DZT_ARCH_ARM_HAS_NEON -march=armv8-a+crypto
  else
    NODE_SRCS += $(ZT)/node/AES_aesni.cpp
    CXXFLAGS += -msse -msse2 -maes -mpclmul
  endif
endif

OBJS := $(patsubst $(ZT)/node/%.cpp,$(OUT)/obj/node/%.o,$(NODE_SRCS)) \
        $(patsubst %.cpp,$(OUT)/obj/glue/%.o,$(GLUE_SRCS))

all: $(OUT)/libztcore.a

# Every object is rebuilt when the compiler or its flags change (a limit
# above, say): the stamp's name carries their checksum.
FLAGS_STAMP := $(OUT)/flags.$(shell echo '$(CXX) $(CXXFLAGS)' | cksum | cut -d' ' -f1)
$(FLAGS_STAMP):
	@mkdir -p $(OUT)
	@rm -f $(OUT)/flags.*
	@touch $@
$(OBJS): $(FLAGS_STAMP)

$(OUT)/libztcore.a: $(OBJS)
	@rm -f $@
	$(AR) rcs $@ $^

$(OUT)/obj/node/%.o: $(ZT)/node/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OUT)/obj/glue/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf -- $(OUT)

.PHONY: all clean

-include $(OBJS:.o=.d)
