#!/usr/bin/env bash
# Stops the test network and deletes its state (identities, the network).
set -euo pipefail
. "$(dirname "$0")/env.sh"
cd "$E2E_DIR"
docker compose --profile extra down -v
rm -rf "$ZTNX_STATE_DIR"
