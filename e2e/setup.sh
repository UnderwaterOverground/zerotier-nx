#!/usr/bin/env bash
# Generates keys and .conf files under state/ and brings up the peers.
# Idempotent; re-run after `down.sh` for a fresh set of keys.
#
# Clients (all with the server as a peer unless noted):
#   client   10.7.0.2  also peer2 and the 10.123.0.0/24 subnet
#   preload  10.7.0.3  for the LD_PRELOAD shim (with the subnet)
#   nosubnet           preload's keys without the subnet
#   bg       10.7.0.4  PersistentKeepalive 3
#   psk      10.7.0.5  with a PresharedKey (badpsk: the same with a wrong one)
#   roam     10.7.0.6
#   noep     10.7.0.7  no Endpoint: the server contacts it (172.31.2.30:41649)
#   dns      10.7.0.8  Endpoint by name (wg-server-later, see run-tests.sh)
# AmneziaWG clients (peers of the awg server, 10.7.1.1):
#   awgclient 10.7.1.2  (awg-plain: the same keys without the AmneziaWG keys)
#   awgswitch 10.7.1.3  for a console on the LAN, via the published port
#                       (ZTNX_LAN_IP overrides the host address it uses)
# AmneziaWG 3 clients (peers of the header-protected awg1, 10.7.2.1):
#   awghp 10.7.2.2  (awghp-nokey: the same without HeaderProtectionKey)
#   awghpswitch 10.7.2.3  for a console, via the published port 51822
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p state
docker compose --profile peer build -q peer awg-peer

if [[ ! -s state/keys.txt ]]; then
  # Plain docker run: the compose service's mounts would create the .conf
  # paths as directories before they exist.
  docker run --rm --entrypoint sh ztnx-e2e-peer -c '
    for n in server peer2 client preload bg psk roam noep dns; do
      k=$(wg genkey); echo "$n $k $(echo "$k" | wg pubkey) $(wg genpsk)"
    done' > state/keys.txt
fi
for n in awg awgclient awgswitch awghpserver awghp awghpswitch; do  # added later: an older state/ may lack them
  grep -q "^$n " state/keys.txt || docker run --rm --entrypoint sh ztnx-e2e-peer -c \
    "k=\$(wg genkey); echo \"$n \$k \$(echo \"\$k\" | wg pubkey) \$(wg genpsk)\"" >> state/keys.txt
done
# The AmneziaWG 3 header protection key (any 32 bytes; `awg genkey` makes one).
grep -q "^hpkey " state/keys.txt || echo "hpkey $(head -c 32 /dev/urandom | base64) - -" >> state/keys.txt
key() { awk -v n="$1" -v f="$2" '$1==n {print $f}' state/keys.txt; }  # f: 2 private, 3 public, 4 psk
SERVER=172.31.2.20
PEER2=172.31.2.21
AWG_SERVER=172.31.2.22
LAN_IP=${ZTNX_LAN_IP:-$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')}
# The obfuscation both sides of the AmneziaWG tunnel agree on: junk before
# handshakes, padded handshake messages, disguised headers (H4 a range).
AWG="Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 22
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4000000-4999999"
# AmneziaWG 3 on top: header protection, which needs S1-S4 of 12 or more.
AWG3="Jc = 2
Jmin = 30
Jmax = 60
S1 = 20
S2 = 31
S3 = 16
S4 = 14
H1 = 11111
H2 = 22222
H3 = 33333
H4 = 40000-49999
HeaderProtectionKey = $(key hpkey 2)
RandomTrailers = on
ContentPaddingAddition = 1-64"

client() {  # name address peers...
  local name=$1 addr=$2; shift 2
  {
    echo "[Interface]"
    echo "# Name = $name"
    echo "PrivateKey = $(key "$name" 2)"
    echo "Address = $addr"
    printf '%s\n' "$@"
  } > "state/$name.conf"
}
server_peer() {  # name allowed [extra lines...]
  local name=$1 allowed=$2; shift 2
  printf '\n[Peer]\n# Name = %s\nPublicKey = %s\nAllowedIPs = %s\n' "$name" "$(key "$name" 3)" "$allowed"
  printf '%s\n' "$@"
}
S="[Peer]
# Name = server
PublicKey = $(key server 3)
Endpoint = $SERVER:51820"

client client 10.7.0.2/24 "" "$S" "AllowedIPs = 10.7.0.1/32, 10.123.0.0/24" "" \
  "[Peer]" "# Name = second" "PublicKey = $(key peer2 3)" "AllowedIPs = 10.7.0.9/32" "Endpoint = $PEER2:51820"
client preload 10.7.0.3/24 "" "$S" "AllowedIPs = 10.7.0.1/32, 10.123.0.0/24"
sed 's/, 10.123.0.0\/24//' state/preload.conf > state/nosubnet.conf
client bg 10.7.0.4/24 "" "$S" "AllowedIPs = 10.7.0.1/32" "PersistentKeepalive = 3"
client psk 10.7.0.5/24 "" "$S" "AllowedIPs = 10.7.0.1/32" "PresharedKey = $(key psk 4)"
sed "s|PresharedKey = .*|PresharedKey = $(key roam 4)|" state/psk.conf > state/badpsk.conf
client roam 10.7.0.6/24 "" "$S" "AllowedIPs = 10.7.0.1/32"
client noep 10.7.0.7/24 "ListenPort = 41649" "" "[Peer]" "# Name = server" "PublicKey = $(key server 3)" "AllowedIPs = 10.7.0.1/32"
client dns 10.7.0.8/24 "" "[Peer]" "# Name = server" "PublicKey = $(key server 3)" "AllowedIPs = 10.7.0.1/32" "Endpoint = wg-server-later:51820"
printf '[Interface]\nPrivateKey = not-a-key\nAddress = 10.7.0.99/24\n' > state/bad.conf
A="[Peer]
# Name = awg-server
PublicKey = $(key awg 3)
AllowedIPs = 10.7.1.1/32"
client awgclient 10.7.1.2/24 "$AWG" "" "$A" "Endpoint = $AWG_SERVER:51820"
grep -v -E '^(Jc|Jmin|Jmax|S[1-4]|H[1-4]) ' state/awgclient.conf > state/awg-plain.conf
client awgswitch 10.7.1.3/24 "$AWG" "" "$A" "Endpoint = ${LAN_IP:-192.0.2.1}:51821" "PersistentKeepalive = 25"
A3="[Peer]
# Name = awg3-server
PublicKey = $(key awghpserver 3)
AllowedIPs = 10.7.2.1/32"
client awghp 10.7.2.2/24 "$AWG3" "" "$A3" "Endpoint = $AWG_SERVER:51821"
grep -v '^HeaderProtectionKey ' state/awghp.conf > state/awghp-nokey.conf
client awghpswitch 10.7.2.3/24 "$AWG3" "" "$A3" "Endpoint = ${LAN_IP:-192.0.2.1}:51822" "PersistentKeepalive = 25"

{
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.7.0.1/24\nListenPort = 51820\n' "$(key server 2)"
  server_peer client 10.7.0.2/32
  server_peer preload 10.7.0.3/32
  server_peer bg 10.7.0.4/32
  server_peer psk 10.7.0.5/32 "PresharedKey = $(key psk 4)"
  server_peer roam 10.7.0.6/32
  server_peer noep 10.7.0.7/32 "Endpoint = 172.31.2.30:41649" "PersistentKeepalive = 5"
  server_peer dns 10.7.0.8/32
} > state/wg0.conf
{
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.7.0.9/24\nListenPort = 51820\n' "$(key peer2 2)"
  server_peer client 10.7.0.2/32
} > state/wg0-peer2.conf
{
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.7.1.1/24\nListenPort = 51820\n%s\n' "$(key awg 2)" "$AWG"
  server_peer awgclient 10.7.1.2/32
  server_peer awgswitch 10.7.1.3/32
} > state/awg0.conf
{
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.7.2.1/24\nListenPort = 51821\n%s\n' "$(key awghpserver 2)" "$AWG3"
  server_peer awghp 10.7.2.2/32
  server_peer awghpswitch 10.7.2.3/32
} > state/awg1.conf

docker compose --profile peer up -d peer peer2 web iperf awg-peer
for _ in $(seq 30); do
  docker compose exec -T peer wg show wg0 >/dev/null 2>&1 && docker compose exec -T awg-peer awg show awg1 >/dev/null 2>&1 && break
  sleep 1
done
echo "server: 10.7.0.1 at $SERVER:51820; peer2: 10.7.0.9 at $PEER2:51820"
echo "awg server: 10.7.1.1 at $AWG_SERVER:51820 (from the LAN: ${LAN_IP:-?}:51821)"
echo "awg 3 server (header protection): 10.7.2.1 at $AWG_SERVER:51821 (from the LAN: ${LAN_IP:-?}:51822)"
echo "confs:  e2e/state/{client,preload,bg,psk,roam,noep,dns,awgclient,awg-plain,awgswitch,awghp,awghp-nokey,awghpswitch}.conf"
