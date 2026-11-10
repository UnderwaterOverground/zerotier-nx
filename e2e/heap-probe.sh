#!/usr/bin/env bash
# Memory probe (run setup.sh first): replays a Moonlight-like session through
# the interpose shim, built with the Switch's buffer limits, and prints the
# Rust heap after each phase. See native/interpose/heap_probe.c.
set -euo pipefail
cd "$(dirname "$0")"
PEER_IP=10.7.0.1
docker compose build -q ztnx-build >/dev/null 2>&1
docker compose run --rm -e CARGO_PROFILE_FLAG=--release -e RUST_PROFILE_DIR=release \
  -e ZTNX_FFI_FEATURES=switch-limits ztnx-build >/dev/null
docker compose exec -T web pkill -f udp-blaster >/dev/null 2>&1 || true
docker compose exec -T -d web python3 -c "$(cat udp-blaster.py)" 9000 udp-blaster
docker compose run --rm -T -e ZTNX_CONF=/state/preload.conf -e ZTNX_PORT=41642 -e ZTNX_WAIT_READY=1 \
  -e LD_PRELOAD=/src/target/linux/libztnx_interpose.so \
  --entrypoint /src/target/linux/heap-probe ztnx "$PEER_IP"
