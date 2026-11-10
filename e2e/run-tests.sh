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

# ---- 2. The same across threads (ztnx-c): the runtime's loop carries frames
# ----    between the stack and ZeroTier while this thread uses sockets.
echo "== runtime =="
check "the runtime's own tests (a fake engine)" client /out/runtime-test
client sh -c 'pkill -x ztnx-c; mkdir -p /state/main' >/dev/null 2>&1
docker compose exec -T -d client sh -c "/out/ztnx-c --state /state/main --join $NW --gen-identity --log --echo-test $PEER_IP --sleep-test --for 90 > /state/main/log 2>&1"
check "ztnx-c starts" wait_log 20 '^node: ' /state/main/log
MAIN_ADDR=$(client sed -n 's/^node: //p' /state/main/log)
./ctl.sh authorize "$MAIN_ADDR" >/dev/null
check "the network comes up" wait_log 75 '^network: OK ip=10\.147\.17\.' /state/main/log
check "TCP and UDP echo from another thread" wait_log 40 '^echo: ok' /state/main/log
check "suspend closes the socket within 2.5 s" wait_log 20 '^suspend: ok .*socket closed' /state/main/log
check "echo again after resume" wait_log 60 '^echo after resume: ok' /state/main/log
check "ztnx-c reports success" wait_log 10 '^result: ok' /state/main/log
echo "--- ztnx-c log ---"; client cat /state/main/log | sed 's/^/    /'

# ---- 3. Unmodified programs through the socket layer (the LD_PRELOAD shim,
# ----    the code the bsd:u MITM uses).
echo "== socket layer =="
MAIN_IP=$(client sed -n 's/^network: OK ip=\([0-9.]*\).*/\1/p' /state/main/log | tail -1)
shim() { docker compose exec -T -e LD_PRELOAD=/out/libztnx_interpose.so -e ZTNX_STATE=/state/main -e ZTNX_NWID="$NW" -e ZTNX_WAIT_READY=1 "$@"; }
shim client /out/vsock-test "$PEER_IP" 172.31.2.20:7 "$MAIN_IP" > "$ZTNX_STATE_DIR/client/vsock.log" 2>&1
check "the socket patterns apps use (vsock-test)" test $? -eq 0
sed 's/^/    /' "$ZTNX_STATE_DIR/client/vsock.log" | grep -v '^    PASS' | head -20
check "curl fetches a page from the peer" sh -c "docker compose exec -T -e LD_PRELOAD=/out/libztnx_interpose.so -e ZTNX_STATE=/state/main -e ZTNX_NWID=$NW -e ZTNX_WAIT_READY=1 client curl -s -m 20 http://$PEER_IP:8080/ | grep -q 'hello from the peer'"
TCP_MBIT=$(shim client iperf3 -c "$PEER_IP" -t 5 -J 2>/dev/null | jq -r '.end.sum_received.bits_per_second / 1e6 | floor' 2>/dev/null)
check "iperf3 TCP to the peer, 5 s (${TCP_MBIT:-?} Mbit/s, at least 50)" test "${TCP_MBIT:-0}" -ge 50
UDP_MBIT=$(shim client iperf3 -c "$PEER_IP" -u -b 20M -l 1000 -t 5 -J 2>/dev/null | jq -r '.end.sum.bits_per_second / 1e6 | floor' 2>/dev/null)
check "iperf3 UDP 20 Mbit/s to the peer (${UDP_MBIT:-?} Mbit/s sent)" test "${UDP_MBIT:-0}" -ge 19

echo
if [ "$fails" -eq 0 ]; then echo "all passed"; else echo "$fails failed"; fi
exit "$fails"
