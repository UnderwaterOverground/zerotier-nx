#!/usr/bin/env bash
# Builds the Linux artifacts used by e2e tests (runs inside the rust:1 image):
# ztnx-host, ztnx-c, the LD_PRELOAD shim and the vsock test client.
set -euo pipefail
cd /src
export CARGO_TARGET_DIR=/src/target/linux
cargo build -q -p ztnx-host -p ztnx-ffi ${CARGO_PROFILE_FLAG:-} ${ZTNX_FFI_FEATURES:+--features ztnx-ffi/$ZTNX_FFI_FEATURES}
out=/src/target/linux
inc="-Icrates/ztnx-ffi/include -Inative/driver -Inative/runtime -Inative/vsock"
cc -c -fPIC -O1 -g $inc native/driver/ztnx_driver.c -o $out/ztnx_driver.o
cc -c -fPIC -O1 -g $inc native/driver/ztnx_dns.c -o $out/ztnx_dns.o
cc -c -fPIC -O1 -g $inc native/driver/ztnx_update.c -o $out/ztnx_update.o
cc -c -fPIC -O1 -g -DZTNX_BUILD_UNIX=$(date +%s) $inc native/driver/ztnx_app.c -o $out/ztnx_app.o
c++ -std=c++17 -shared -fPIC -O1 -g -Wall $inc -o $out/libztnx_interpose.so \
  native/vsock/vsock.cpp native/runtime/runtime.cpp native/interpose/interpose.cpp \
  $out/ztnx_driver.o $out/ztnx_app.o $out/ztnx_dns.o $out/ztnx_update.o $out/${RUST_PROFILE_DIR:-debug}/libztnx_ffi.a -lpthread -ldl -lm
cc -O1 -g -Wall -DZTNX_BUILD_UNIX=$(date +%s) $inc -o $out/ztnx-c native/host/main.c native/driver/ztnx_driver.c native/driver/ztnx_app.c native/driver/ztnx_dns.c native/driver/ztnx_update.c \
  $out/${RUST_PROFILE_DIR:-debug}/libztnx_ffi.a -lpthread -ldl -lm
cc -O1 -g -Wall -o $out/vsock-test native/interpose/vsock_test.c
cc -O1 -g -Wall -o $out/heap-probe native/interpose/heap_probe.c -ldl
# A fixed path for the compose service, whichever profile was built.
mkdir -p $out/bin && cp $out/${RUST_PROFILE_DIR:-debug}/ztnx-host $out/bin/ztnx-host
echo "built (${RUST_PROFILE_DIR:-debug}): $out/bin/ztnx-host, $out/ztnx-c, $out/libztnx_interpose.so, $out/vsock-test"
