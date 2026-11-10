#!/usr/bin/env bash
# End-to-end tests against the Docker test network (e2e/setup.sh first).
# Each check prints PASS or FAIL; the exit status is the number of failures.
set -uo pipefail
. "$(dirname "$0")/env.sh"
cd "$E2E_DIR"

fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null; then pass "$name"; else fail "$name"; fi; }
client() { docker compose exec -T client "$@"; }
peer() { docker compose exec -T peer "$@"; }
# Waits up to $1 seconds for a line matching $2 in the client's file $3.
wait_log() {
  local i
  for i in $(seq "$1"); do client grep -q -- "$2" "$3" 2>/dev/null && return 0; sleep 1; done
  return 1
}

NW=$(./ctl.sh nwid)
PEER_IP=$(peer zerotier-cli listnetworks -j | jq -r --arg n "$NW" '.[] | select(.nwid==$n) | .assignedAddresses[0]' | cut -d/ -f1)
echo "network $NW, peer $PEER_IP"

# ---- 1. The pieces on one thread (zt-smoke): identity, join, authorize, ARP,
# ----    UDP out and back, ping and TCP in.
echo "== smoke =="
client sh -c 'pkill -x zt-smoke; rm -rf /state/smoke && mkdir -p /state/smoke' >/dev/null 2>&1
docker compose exec -T -d client sh -c "/out/zt-smoke --state /state/smoke --join $NW --gen-identity --udp-echo $PEER_IP:7 --udp-echo-size 2000 --tcp-echo-server 7777 --for 90 > /state/smoke/log 2>&1"
check "a new identity is generated" wait_log 20 '^node: ' /state/smoke/log
ADDR=$(client sed -n 's/^node: //p' /state/smoke/log)
check "an unauthorized node is told so" wait_log 30 'network: ACCESS_DENIED' /state/smoke/log
./ctl.sh authorize "$ADDR" >/dev/null
check "once authorized it gets an address" wait_log 75 'network: OK ip=10\.147\.17\.' /state/smoke/log
OUR_IP=$(client sed -n 's/^network: OK ip=\([0-9.]*\).*/\1/p' /state/smoke/log | tail -1)
check "UDP echo of 2000 bytes (two ZeroTier datagrams each way)" wait_log 30 'udp echo: ok, 2000 bytes' /state/smoke/log
check "the peer can ping us" peer ping -c 3 -W 2 -q "$OUR_IP"
check "TCP echo, 300 KB, from the peer" peer sh -c "head -c 300000 /dev/urandom > /tmp/blob && socat -t 5 - TCP4:$OUR_IP:7777 < /tmp/blob | cmp -s - /tmp/blob"
# (A ping too big for one ZeroTier datagram is not answered: the netstack
# builds replies no larger than it lets TCP send. Large packets are UDP's.)
check "a 1300-byte ping" peer ping -c 3 -W 2 -q -s 1300 "$OUR_IP"
client pkill -x zt-smoke >/dev/null 2>&1
echo "--- smoke log ---"; client cat /state/smoke/log | sed 's/^/    /'
./ctl.sh api DELETE "/controller/network/$NW/member/$ADDR" >/dev/null 2>&1

echo
if [ "$fails" -eq 0 ]; then echo "all passed"; else echo "$fails failed"; fi
exit "$fails"
