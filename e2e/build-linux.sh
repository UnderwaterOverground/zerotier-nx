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
inc="-Icrates/ztnx-ffi/include -Inative/zt"
c++ -std=c++17 -O1 -g -Wall $inc -o $out/zt-smoke native/host/zt_smoke.cpp $out/zt/libztcore.a $out/$profile/libztnx_ffi.a -lpthread -ldl -lm
echo "built ($profile): $out/zt-smoke"
