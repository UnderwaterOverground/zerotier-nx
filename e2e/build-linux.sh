#!/usr/bin/env bash
# Builds the Linux artifacts the e2e tests run, inside the client container:
# the Rust stack, ZeroTier's core with its glue, and the host tools. Output
# goes to /out (target/linux in the main checkout).
set -euo pipefail
cd /src
out=/out
export CARGO_TARGET_DIR=$out
profile=${RUST_PROFILE_DIR:-debug}
cargo build -q -p ztnx-ffi ${CARGO_PROFILE_FLAG:-} ${ZTNX_FFI_FEATURES:+--features ztnx-ffi/$ZTNX_FFI_FEATURES}
make -s -C native/zt PLATFORM=host OUT=$out/zt -j"$(nproc)"
inc="-Icrates/ztnx-ffi/include -Inative/zt -Inative/driver -Inative/runtime -Inative/vsock -Inative/host"
libs="$out/zt/libztcore.a $out/$profile/libztnx_ffi.a -lpthread -ldl -lm"
c++ -std=c++17 -O1 -g -Wall $inc -o $out/zt-smoke native/host/zt_smoke.cpp $libs
for f in driver dns update; do cc -c -fPIC -O1 -g -Wall $inc native/driver/ztnx_$f.c -o $out/ztnx_$f.o; done
cc -c -fPIC -O1 -g -Wall -DZTNX_BUILD_UNIX=$(date +%s) $inc native/driver/ztnx_app.c -o $out/ztnx_app.o
objs="$out/ztnx_driver.o $out/ztnx_app.o $out/ztnx_dns.o $out/ztnx_update.o"
common="-fPIC native/runtime/runtime.cpp native/runtime/zt_link.cpp native/vsock/vsock.cpp native/host/session.cpp"
c++ -std=c++17 -O1 -g -Wall $inc -o $out/ztnx-c native/host/main.cpp $common $objs $libs
c++ -std=c++17 -O1 -g -Wall $inc -o $out/runtime-test native/host/runtime_test.cpp native/runtime/runtime.cpp $out/ztnx_driver.o $out/$profile/libztnx_ffi.a -lpthread -ldl -lm
c++ -std=c++17 -shared -fPIC -O1 -g -Wall $inc -o $out/libztnx_interpose.so native/interpose/interpose.cpp $common $objs $libs
cc -O1 -g -Wall -o $out/vsock-test native/interpose/vsock_test.c
echo "built ($profile): $out/zt-smoke, $out/ztnx-c, $out/runtime-test, $out/libztnx_interpose.so, $out/vsock-test"
