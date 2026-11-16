# Top-level entry points. Switch builds run inside the ztnx-build Docker image
# (devkitA64 + libnx + Rust nightly) so nothing beyond Docker is needed on the
# host. Set IN_DOCKER=1 to run the Switch steps directly (e.g. in CI).

SWITCH_TARGET := aarch64-nintendo-switch-freestanding
# Build time: a floor for "is the console's clock plausible" (TLS needs it).
BUILD_UNIX := $(shell date +%s)
export ZTNX_BUILD_UNIX := $(BUILD_UNIX)
RUST_SWITCH_FLAGS := --release --target $(SWITCH_TARGET) -Zbuild-std=core,alloc -Zbuild-std-features=optimize_for_size
# A panic aborts at once, without formatting a message nobody would see:
# that keeps core's formatting code out of the sysmodule.
RUST_SWITCH_RUSTFLAGS := -Zunstable-options -Cpanic=immediate-abort
DOCKER_IMAGE := ztnx-build

ifeq ($(IN_DOCKER),1)
  SW :=
else
  SW := docker run --rm -v "$(CURDIR)":/src -v ztnx-cargo-registry:/opt/cargo/registry -e CARGO_TARGET_DIR=/src/target/switch -w /src $(DOCKER_IMAGE)
endif

.PHONY: publish release overlay mitm-test nxlink-mitm-test speedtest nxlink-speedtest all host-test host-c e2e sysmodule libstratosphere docker-image rust-switch nro nxlink clean

all: host-test

# Everything that runs on this machine without Docker or a ZeroTier network.
host-test: zt-selftest runtime-test routes-test
	cargo test --workspace

# End-to-end tests against a ZeroTier network in Docker: a self-hosted
# controller and a stock zerotier-one peer (needs internet: the nodes meet
# through ZeroTier's root servers).
e2e:
	e2e/setup.sh
	e2e/run-tests.sh

# The host tools (macOS; Linux builds are e2e/build-linux.sh's). They share
# the sysmodule's driver, runtime and socket layer, and link ZeroTier's core.
HOST_INC := -Icrates/ztnx-ffi/include -Inative/driver -Inative/runtime -Inative/vsock -Inative/zt -Inative/host
HOST_C_SRCS := native/driver/ztnx_driver.c native/driver/ztnx_app.c native/driver/ztnx_dns.c native/driver/ztnx_update.c
HOST_CXX_SRCS := native/runtime/runtime.cpp native/runtime/zt_link.cpp native/vsock/vsock.cpp native/host/session.cpp
HOST_OBJS := target/ztnx_driver.o target/ztnx_app.o target/ztnx_dns.o target/ztnx_update.o
HOST_LIBS := target/zt-host/libztcore.a target/debug/libztnx_ffi.a -framework CoreFoundation -framework Security

.PHONY: host-objs
host-objs: zt-host FORCE
	cargo build -p ztnx-ffi
	$(CC) -c -O1 -g -Wall $(HOST_INC) native/driver/ztnx_driver.c -o target/ztnx_driver.o
	$(CC) -c -O1 -g -Wall -DZTNX_BUILD_UNIX=$(BUILD_UNIX) $(HOST_INC) native/driver/ztnx_app.c -o target/ztnx_app.o
	$(CC) -c -O1 -g -Wall $(HOST_INC) native/driver/ztnx_dns.c -o target/ztnx_dns.o
	$(CC) -c -O1 -g -Wall $(HOST_INC) native/driver/ztnx_update.c -o target/ztnx_update.o

# ztnx-c: the sysmodule's parts without the socket MITM (see native/host/main.cpp).
host-c: host-objs
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra $(HOST_INC) -o target/ztnx-c native/host/main.cpp $(HOST_CXX_SRCS) $(HOST_OBJS) $(HOST_LIBS)

FORCE:

docker-image:
	docker build -t $(DOCKER_IMAGE) docker

rust-switch:
	$(SW) env RUSTFLAGS="$(RUST_SWITCH_RUSTFLAGS)" cargo build -p ztnx-ffi $(RUST_SWITCH_FLAGS)

nro: rust-switch
	$(SW) make -C switch/app ZTNX_BUILD_UNIX=$(BUILD_UNIX)

# Send the NRO to hbmenu's netloader (press Y on the console first) and stream
# its stdout back. NXLINK_HOST is the console's IP; broadcast discovery does not
# work from inside Docker Desktop.
# Atmosphère's libstratosphere (pinned to the console's Atmosphère, 1.12.2).
LIBSTRAT := third_party/Atmosphere/libraries/libstratosphere/lib/nintendo_nx_arm64_armv8a/release/libstratosphere.a
# Fixes to Atmosphère's libraries that zerotier-nx needs (see patches/),
# applied to the submodule before building; a changed patch rebuilds.
ATMOSPHERE_PATCHES := $(sort $(wildcard patches/atmosphere-*.patch))
libstratosphere: $(LIBSTRAT)
$(LIBSTRAT): $(ATMOSPHERE_PATCHES)
	@for p in $(ATMOSPHERE_PATCHES); do \
	  git -C third_party/Atmosphere apply --reverse --check ../../$$p 2>/dev/null || \
	  git -C third_party/Atmosphere apply ../../$$p || exit 1; \
	done
	$(SW) make -C third_party/Atmosphere/libraries/libstratosphere -j8
	@# Its precompiled header is built at -O2. Where GCC accepts it (a fresh
	@# build; not when git describes the tree differently than when it was
	@# made) the sysmodule's code from Atmosphère's headers is -O2 rather
	@# than -Os, and ~25 KB larger. Remove it so every build is the same.
	rm -rf third_party/Atmosphere/libraries/libstratosphere/include/stratosphere.hpp.gch

# ZeroTier's core (third_party/ZeroTierOne/node) with our changes to it
# (patches/zerotier-*.patch, applied to the submodule's working tree), built
# as target/zt-switch/libztcore.a and, for host tests and e2e, target/zt-host.
ZEROTIER_PATCHES := $(sort $(wildcard patches/zerotier-*.patch))
.PHONY: zerotier-patches zt-switch zt-host
zerotier-patches:
	@tools/zerotier-patches.sh

zt-switch: zerotier-patches
	$(SW) make -C native/zt PLATFORM=switch -j8

zt-host: zerotier-patches
	$(MAKE) -C native/zt PLATFORM=host -j8

# The glue's check that C++ exceptions work, on this machine. (From a
# worktree, where the submodule is empty: make zt-selftest ZT=<main checkout>/third_party/ZeroTierOne)
.PHONY: zt-selftest
zt-selftest: zt-host
	$(CC) -c -Inative/zt -Icrates/ztnx-ffi/include native/host/zt_selftest.c -o target/zt_selftest.o
	$(CXX) -o target/zt-selftest target/zt_selftest.o target/zt-host/libztcore.a
	target/zt-selftest

# Then holds its memory at exactly tools/footprint.sh's target (it resizes the heap
# and asks for one more build when the code size moved).
sysmodule: rust-switch zt-switch $(LIBSTRAT)
	$(SW) make -C switch/sysmodule ZTNX_BUILD_UNIX=$(BUILD_UNIX) dist
	$(SW) tools/footprint.sh || { [ $$? -eq 3 ] && $(SW) make -C switch/sysmodule ZTNX_BUILD_UNIX=$(BUILD_UNIX) dist && $(SW) tools/footprint.sh; }

# Publish to GitHub: only main and v* tags (the `github` remote's push
# refspecs); other branches stay on the private Gitea. Pushing a v* tag
# builds a draft release there.
publish:
	git push github

# Release zip for the SD card root: dist/zerotier-nx-<version>.zip
release:
	tools/package-release.sh

# Tesla/Ultrahand overlay: status, on/off and login QR (switch/overlay).
overlay:
	$(SW) make -C switch/overlay

# Socket-virtualization suite as plain homebrew, through the sysmodule's
# bsd:u MITM. Needs TCP and UDP echo on port 7 of a device on the ZeroTier
# network (MITM_PEER; tools/echo-server.py, or the e2e peer container).
mitm-test:
	$(SW) make -C switch/mitm-test

nxlink-mitm-test: mitm-test target/nxlink
	@test -n "$(NXLINK_HOST)" -a -n "$(MITM_PEER)" || (echo "set NXLINK_HOST=<switch ip> MITM_PEER=<the peer's ZeroTier ip>" && false)
	script -q target/nxlink-mitm.log target/nxlink -a $(NXLINK_HOST) -s switch/mitm-test/mitm-test.nro $(MITM_PEER) $(MITM_PASSTHROUGH)

# Throughput (TCP/UDP each way), per-call socket costs and SD card writes,
# as plain homebrew through the MITM. Run
# tools/speedtest-server.py on a wired machine and give it both of that
# machine's addresses (LAN, then ZeroTier): SPEEDTEST_SERVERS="<lan ip> <zerotier ip>".
speedtest: rust-switch
	$(SW) make -C switch/speedtest

nxlink-speedtest: speedtest target/nxlink
	@test -n "$(NXLINK_HOST)" -a -n "$(SPEEDTEST_SERVERS)" || (echo "set NXLINK_HOST=<switch ip> SPEEDTEST_SERVERS=\"<lan ip> <zerotier ip>\"" && false)
	script -q target/nxlink-speedtest.log target/nxlink -a $(NXLINK_HOST) -s switch/speedtest/speedtest.nro $(SPEEDTEST_ARGS) $(SPEEDTEST_SERVERS)

nxlink: nro target/nxlink
	@test -n "$(NXLINK_HOST)" || (echo "set NXLINK_HOST=<switch ip>" && false)
	# `script` gives nxlink a pty so the console's log streams line by line
	# (also into target/nxlink.log).
	script -q target/nxlink.log target/nxlink -a $(NXLINK_HOST) -s switch/app/ztnx-app.nro

# nxlink built natively (switchbrew/switch-tools): the console has to connect
# back for stdout, which is simplest without Docker's port mapping.
target/nxlink:
	rm -rf target/switch-tools && git clone -q --depth 1 https://github.com/switchbrew/switch-tools.git target/switch-tools
	$(CC) -O2 -o $@ target/switch-tools/src/nxlink.c -lz

clean:
	cargo clean
	$(SW) make -C switch/app ZTNX_BUILD_UNIX=$(BUILD_UNIX) clean

# Interpose shim (run unmodified programs through the socket virtualization
# layer) and its test client, for macOS.
.PHONY: interpose routes-test runtime-test
interpose: target/libztnx_interpose.dylib target/vsock-test

target/libztnx_interpose.dylib: host-objs
	$(CXX) -std=c++17 -O1 -g -Wall -dynamiclib -o $@ $(HOST_INC) native/interpose/interpose.cpp $(HOST_CXX_SRCS) $(HOST_OBJS) $(HOST_LIBS)

# The socket layer's route check (links the interpose shim).
routes-test: target/libztnx_interpose.dylib
	$(CXX) -std=c++17 -O1 -g -Wall $(HOST_INC) -o target/routes-test native/host/routes_test.cpp $<
	target/routes-test

# The runtime against a fake engine: who runs engine code and with what
# held, wake-ups, timers, pause and suspend.
runtime-test: host-objs
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra $(HOST_INC) -o target/runtime-test native/host/runtime_test.cpp native/runtime/runtime.cpp \
		target/ztnx_driver.o target/debug/libztnx_ffi.a -framework CoreFoundation -framework Security
	target/runtime-test

target/vsock-test: native/interpose/vsock_test.c
	$(CC) -O1 -g -Wall -o $@ $<
