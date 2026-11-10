#!/usr/bin/env bash
# End-to-end tests against the local WireGuard peers (run setup.sh first).
# Builds ztnx-host for Linux and runs it on the compose network next to them.
set -uo pipefail
cd "$(dirname "$0")"
SERVER_IP=10.7.0.1
PEER2_IP=10.7.0.9
fails=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; fails=$((fails + 1)); }
key() { awk -v n="$1" -v f="$2" '$1==n {print $f}' state/keys.txt; }  # f: 3 public

docker compose build -q ztnx-build >/dev/null 2>&1
docker compose run --rm -e CARGO_PROFILE_FLAG=--release -e RUST_PROFILE_DIR=release ztnx-build >/dev/null 2>&1 \
  || { echo "build failed"; exit 1; }
ztnx() { docker compose run --rm -T ztnx "$@"; }
peer() { docker compose exec -T peer "$@"; }
# Seconds since the server's last handshake with a client (empty: never).
handshake_age() {
  local pub; pub=$(key "$1" 3)
  local t; t=$(peer wg show wg0 latest-handshakes | awk -v k="$pub" '$1==k {print $2}')
  [[ -n "$t" && "$t" != 0 ]] && echo $(( $(date +%s) - t ))
}
wait_handshake() {  # client, timeout secs
  for _ in $(seq "$2"); do
    local age; age=$(handshake_age "$1")
    [[ -n "$age" && "$age" -lt 60 ]] && return 0
    sleep 1
  done
  return 1
}
bg() {  # name, args...: a client in the background
  local name=$1; shift
  docker compose run --rm -T -d --name "ztnx-e2e-$name" ztnx "$@" >/dev/null
}
stop_bg() { docker rm -f "ztnx-e2e-$1" >/dev/null 2>&1; }

# 1. Outbound TCP+UDP echo after a handshake.
if ztnx up --conf /state/client.conf --port 41641 --echo-test "$SERVER_IP" --expect-handshake >/tmp/ztnx-e2e-1.log 2>&1; then pass "echo + handshake"; else fail "echo + handshake (see /tmp/ztnx-e2e-1.log)"; fi

# 2. Handshake retries: the server drops our packets for 20 s after we start.
peer iptables -I INPUT -s 172.31.2.30 -p udp -j DROP
bg retry up --conf /state/roam.conf --port 41650
sleep 20
peer iptables -D INPUT -s 172.31.2.30 -p udp -j DROP
if wait_handshake roam 40; then pass "handshake retried after 20 s of loss"; else fail "handshake retried after 20 s of loss"; fi
stop_bg retry

# 3. Inbound: with a keepalive client up, the server pings us through the tunnel.
bg keep up --conf /state/bg.conf --port 41643
if wait_handshake bg 15 && peer ping -c 5 -W 2 10.7.0.4 >/dev/null; then pass "inbound ICMP"; else fail "inbound ICMP"; fi
# 3b. PersistentKeepalive = 3: packets keep flowing while idle.
rx0=$(peer wg show wg0 transfer | awk -v k="$(key bg 3)" '$1==k {print $2}')
sleep 10
rx1=$(peer wg show wg0 transfer | awk -v k="$(key bg 3)" '$1==k {print $2}')
if [[ $((rx1 - rx0)) -ge 64 ]]; then pass "persistent keepalive (+$((rx1 - rx0)) bytes in 10 s)"; else fail "persistent keepalive (+$((rx1 - rx0)) bytes in 10 s)"; fi
stop_bg keep

# 4-6. Unmodified programs through the socket virtualization layer (the code
# the Switch MITM uses), via LD_PRELOAD.
preload() {  # conf-name, command
  docker compose run --rm -T -e ZTNX_CONF="/state/$1.conf" -e ZTNX_PORT=41642 -e ZTNX_WAIT_READY=1 \
    -e LD_PRELOAD=/src/target/linux/libztnx_interpose.so --entrypoint sh ztnx -c "$2"
}
if preload preload "/src/target/linux/vsock-test $SERVER_IP 172.31.2.20:8080 10.7.0.3" >/tmp/ztnx-e2e-4.log 2>&1; then
  pass "socket virtualization suite (vsock-test)"
else
  fail "socket virtualization suite (see /tmp/ztnx-e2e-4.log)"
fi
if preload preload "curl -s -m 10 http://$SERVER_IP:8080/" 2>/dev/null | grep -q "<html"; then pass "unmodified curl through the tunnel"; else fail "unmodified curl"; fi
udp=$(preload preload "iperf3 -c $SERVER_IP -u -b 50M -l 1200 -t 4 -R -f m 2>&1 | grep receiver" 2>/dev/null)
mbps=$(echo "$udp" | awk '{for (i=1;i<=NF;i++) if ($i=="Mbits/sec") print $(i-1)}')
if awk "BEGIN{exit !(${mbps:-0} >= 47)}"; then pass "UDP 50 Mbit/s stream (got ${mbps} Mbit/s)"; else fail "UDP 50 Mbit/s stream (got ${mbps:-none})"; fi
tcp=$(preload preload "iperf3 -c $SERVER_IP -t 3 -f m 2>&1 | grep receiver" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="Mbits/sec") print $(i-1)}')
if awk "BEGIN{exit !(${tcp:-0} >= 100)}"; then pass "TCP bulk upload (got ${tcp} Mbit/s)"; else fail "TCP bulk upload (got ${tcp:-none})"; fi

# 7. Inbound connections: nothing filters them (WireGuard has no ACLs).
docker compose run --rm -T -d --name ztnx-e2e-listen -e ZTNX_CONF=/state/preload.conf -e ZTNX_PORT=41642 \
  -e ZTNX_WAIT_READY=1 -e LD_PRELOAD=/src/target/linux/libztnx_interpose.so --entrypoint python3 ztnx -c '
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 7777)); s.listen(5)
while True: time.sleep(1)' >/dev/null
sleep 6
if peer nc -z -w 3 10.7.0.3 7777; then pass "inbound listener reachable"; else fail "inbound listener reachable"; fi
if ! peer nc -z -w 3 10.7.0.3 7778; then pass "closed port refused"; else fail "closed port refused"; fi
stop_bg listen

# 8. A subnet in AllowedIPs goes through the tunnel; without it, not.
if preload preload "curl -s -m 10 http://10.123.0.1:8080/" 2>/dev/null | grep -q "<html"; then pass "subnet via AllowedIPs"; else fail "subnet via AllowedIPs"; fi
if ! preload nosubnet "curl -s -m 5 http://10.123.0.1:8080/" 2>/dev/null | grep -q "<html"; then pass "subnet absent without AllowedIPs"; else fail "subnet absent without AllowedIPs"; fi

# 9. Pre-shared keys: the right one works, a wrong one never handshakes.
if ztnx up --conf /state/psk.conf --port 41644 --echo-test "$SERVER_IP" --expect-handshake >/tmp/ztnx-e2e-9.log 2>&1; then pass "preshared key"; else fail "preshared key (see /tmp/ztnx-e2e-9.log)"; fi
if ! ztnx up --conf /state/badpsk.conf --port 41644 --expect-handshake --duration 15 >/dev/null 2>&1; then pass "wrong preshared key refused"; else fail "wrong preshared key refused"; fi

# 10. A host-name endpoint that only resolves later (the engine re-resolves
# every 30 s while there is no handshake).
bg dns up --conf /state/dns.conf --port 41645
sleep 5
docker exec ztnx-e2e-dns sh -c 'echo "172.31.2.20 wg-server-later" >> /etc/hosts'
if wait_handshake dns 60; then pass "host-name endpoint resolved later"; else fail "host-name endpoint resolved later"; fi
stop_bg dns

# 11. Roaming: the server follows us to a new port.
ztnx up --conf /state/roam.conf --port 41650 --echo-test "$SERVER_IP" >/dev/null 2>&1
if ztnx up --conf /state/roam.conf --port 41651 --echo-test "$SERVER_IP" >/dev/null 2>&1 \
   && peer wg show wg0 endpoints | grep -q "$(key roam 3).*172.31.2.30:41651"; then pass "roaming to a new port"; else fail "roaming to a new port"; fi

# 12. Several peers: echo reaches the second server too.
if ztnx up --conf /state/client.conf --port 41646 --echo-test "$PEER2_IP" >/dev/null 2>&1; then pass "second peer"; else fail "second peer"; fi

# 13. No Endpoint: the server's keepalive finds us.
bg noep up --conf /state/noep.conf --port 41649
if wait_handshake noep 20 && peer ping -c 3 -W 2 10.7.0.7 >/dev/null; then pass "endpoint-less peer contacted by the server"; else fail "endpoint-less peer contacted by the server"; fi
stop_bg noep

# 14. A broken conf: a clear error, and the shim stays out of the way.
if { ztnx check --conf /state/bad.conf 2>&1 || true; } | grep -q "line 2"; then pass "config error names the line"; else fail "config error names the line"; fi
if preload bad "curl -s -m 10 http://172.31.2.20:8080/" 2>/dev/null | grep -q "<html"; then pass "shim disabled on a bad conf"; else fail "shim disabled on a bad conf"; fi

# 15. Sleep and wake (the console's path): echo again within 3 s of resuming.
if docker compose run --rm -T --entrypoint /src/target/linux/ztnx-c ztnx --conf /state/client.conf --port 41652 \
     --echo-test "$SERVER_IP" --sleep-test >/tmp/ztnx-e2e-15.log 2>&1; then pass "echo after suspend/resume ($(grep -o 'in [0-9.]* s' /tmp/ztnx-e2e-15.log))"; else fail "echo after suspend/resume (see /tmp/ztnx-e2e-15.log)"; fi

# 16. AmneziaWG: junk, padded handshakes and disguised headers against a
# real amneziawg-go; the same keys without the obfuscation get nowhere.
AWG_IP=10.7.1.1
if ztnx up --conf /state/awgclient.conf --port 41653 --echo-test "$AWG_IP" --expect-handshake >/tmp/ztnx-e2e-16.log 2>&1; then pass "AmneziaWG echo + handshake"; else fail "AmneziaWG echo + handshake (see /tmp/ztnx-e2e-16.log)"; fi
if ! ztnx up --conf /state/awg-plain.conf --port 41653 --expect-handshake --duration 15 >/dev/null 2>&1; then pass "plain WireGuard refused by the AmneziaWG server"; else fail "plain WireGuard refused by the AmneziaWG server"; fi

# 17. AmneziaWG 3 header protection: the same again with every header
# encrypted, at full speed; the same parameters minus the key get nowhere.
HP_IP=10.7.2.1
if ztnx up --conf /state/awghp.conf --port 41654 --echo-test "$HP_IP" --expect-handshake >/tmp/ztnx-e2e-17.log 2>&1; then pass "AmneziaWG header protection echo + handshake"; else fail "AmneziaWG header protection echo + handshake (see /tmp/ztnx-e2e-17.log)"; fi
if ! ztnx up --conf /state/awghp-nokey.conf --port 41654 --expect-handshake --duration 15 >/dev/null 2>&1; then pass "header protection: no key, no handshake"; else fail "header protection: no key, no handshake"; fi
udp=$(preload awghp "iperf3 -c $HP_IP -u -b 50M -l 1200 -t 4 -R -f m 2>&1 | grep receiver" 2>/dev/null)
mbps=$(echo "$udp" | awk '{for (i=1;i<=NF;i++) if ($i=="Mbits/sec") print $(i-1)}')
if awk "BEGIN{exit !(${mbps:-0} >= 47)}"; then pass "UDP 50 Mbit/s through header protection (got ${mbps} Mbit/s)"; else fail "UDP 50 Mbit/s through header protection (got ${mbps:-none})"; fi
tcp=$(preload awghp "iperf3 -c $HP_IP -t 3 -f m 2>&1 | grep receiver" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="Mbits/sec") print $(i-1)}')
if awk "BEGIN{exit !(${tcp:-0} >= 100)}"; then pass "TCP bulk upload through header protection (got ${tcp} Mbit/s)"; else fail "TCP bulk upload through header protection (got ${tcp:-none})"; fi

echo
if [[ $fails -eq 0 ]]; then echo "all e2e tests passed"; else echo "$fails test(s) failed"; exit 1; fi
