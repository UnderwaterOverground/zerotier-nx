#!/usr/bin/env bash
# Controller and peer helpers for the test network.
#   ctl.sh network            create (or reuse) the test network; prints NWID
#   ctl.sh authorize ADDR     authorize a member
#   ctl.sh deauthorize ADDR
#   ctl.sh members            list members (address, authorized, ip)
#   ctl.sh join-peer SERVICE  make a stock peer container join and authorize it
#   ctl.sh nwid               print the network ID
#   ctl.sh set-network JSON   POST fields on the network (rules, routes, capabilities, tags)
#   ctl.sh set-member ADDR JSON
#   ctl.sh api METHOD PATH [JSON]   raw controller API call
set -euo pipefail
SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
. "$(dirname "$0")/env.sh"
cd "$E2E_DIR"
TOKEN=e2e-controller-token
STATE=$ZTNX_STATE_DIR

dc() { docker compose "$@"; }
api() {
  local method=$1 path=$2 data=${3:-}
  if [ -n "$data" ]; then
    dc exec -T controller curl -sf -X "$method" -H "X-ZT1-Auth: $TOKEN" -H 'Content-Type: application/json' --data "$data" "http://127.0.0.1:9993$path"
  else
    dc exec -T controller curl -sf -X "$method" -H "X-ZT1-Auth: $TOKEN" "http://127.0.0.1:9993$path"
  fi
}
wait_controller() {
  for _ in $(seq 60); do
    if api GET /status >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "controller API not reachable" >&2; return 1
}
nwid() { cat "$STATE/nwid"; }

cmd=${1:-}; shift || true
case "$cmd" in
  network)
    wait_controller
    ctrl=$(api GET /status | jq -r .address)
    if [ -f "$STATE/nwid" ] && api GET "/controller/network/$(nwid)" >/dev/null 2>&1; then
      echo "reusing network $(nwid)" >&2; nwid; exit 0
    fi
    body='{"name":"e2e","private":true,"enableBroadcast":true,"mtu":2800,
           "v4AssignMode":{"zt":true},"v6AssignMode":{"6plane":false,"rfc4193":false,"zt":false},
           "ipAssignmentPools":[{"ipRangeStart":"10.147.17.1","ipRangeEnd":"10.147.17.254"}],
           "routes":[{"target":"10.147.17.0/24","via":null}],
           "rules":[{"type":"ACTION_ACCEPT"}]}'
    api POST "/controller/network/${ctrl}______" "$body" | jq -r .id > "$STATE/nwid"
    echo "created network $(nwid)" >&2; nwid ;;
  authorize)
    api POST "/controller/network/$(nwid)/member/$1" '{"authorized":true}' | jq -c '{address,authorized,ipAssignments}' ;;
  deauthorize)
    api POST "/controller/network/$(nwid)/member/$1" '{"authorized":false}' | jq -c '{address,authorized}' ;;
  members)
    for m in $(api GET "/controller/network/$(nwid)/member" | jq -r 'keys[]'); do
      api GET "/controller/network/$(nwid)/member/$m" | jq -c '{address,authorized,ipAssignments,capabilities,tags}'
    done ;;
  set-network)
    api POST "/controller/network/$(nwid)" "$1" | jq -c '{id,name,rules:(.rules|length),routes:(.routes|length),capabilities:(.capabilities|length),tags:(.tags|length)}' ;;
  set-member)
    addr=$1; shift
    api POST "/controller/network/$(nwid)/member/$addr" "$1" | jq -c '{address,authorized,capabilities,tags}' ;;
  join-peer)
    svc=${1:-peer}; idx=
    ex() { dc exec -T "$svc" "$@"; }
    for _ in $(seq 30); do ex zerotier-cli info >/dev/null 2>&1 && break; sleep 1; done
    addr=$(ex zerotier-cli info -j | jq -r .address)
    ex zerotier-cli join "$(nwid)" >/dev/null
    "$SELF" authorize "$addr" >/dev/null
    st=
    for _ in $(seq 60); do
      ip=$(ex zerotier-cli listnetworks -j | jq -r --arg n "$(nwid)" '.[] | select(.nwid==$n) | .assignedAddresses[0] // empty')
      st=$(ex zerotier-cli listnetworks -j | jq -r --arg n "$(nwid)" '.[] | select(.nwid==$n) | .status')
      if [ "$st" = "OK" ] && [ -n "$ip" ]; then echo "$svc${idx:+[$idx]} $addr $ip"; exit 0; fi
      sleep 1
    done
    echo "$svc did not come up (status=$st)" >&2; exit 1 ;;
  nwid) nwid ;;
  api) api "$@" ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
