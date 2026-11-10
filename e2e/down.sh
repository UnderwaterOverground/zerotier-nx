#!/usr/bin/env bash
# Stops the peers and deletes their state (keys and confs).
set -euo pipefail
cd "$(dirname "$0")"
docker compose --profile peer --profile ztnx down -v --remove-orphans
rm -rf state
