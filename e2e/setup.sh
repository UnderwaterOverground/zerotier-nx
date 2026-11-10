#!/usr/bin/env bash
# Brings up the test network and builds our Linux artifacts:
#   images (built if missing), controller + peer + client containers, the
#   network (10.147.17.0/24, private), the stock peer joined and authorized.
set -euo pipefail
. "$(dirname "$0")/env.sh"
cd "$E2E_DIR"
docker compose up -d controller peer client
./ctl.sh network >/dev/null
./ctl.sh join-peer peer
docker compose exec -T client /src/e2e/build-linux.sh
echo "network $(./ctl.sh nwid) is up"
