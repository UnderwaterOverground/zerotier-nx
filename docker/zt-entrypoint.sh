#!/bin/sh
# Entrypoint shared by the controller and peer images.
# Env: ZEROTIER_API_SECRET (authtoken), ZEROTIER_JOIN_NETWORKS (space separated),
#      ZT_RUN_SERVERS=1 to start the servers the tests talk to: iperf3, an echo
#      on port 7 (UDP and TCP) and a web server on 8080.
set -e
d=/var/lib/zerotier-one
mkdir -p "$d/networks.d"
if [ -n "$ZEROTIER_API_SECRET" ]; then
  printf '%s' "$ZEROTIER_API_SECRET" > "$d/authtoken.secret"
  chmod 600 "$d/authtoken.secret"
fi
for n in $ZEROTIER_JOIN_NETWORKS; do touch "$d/networks.d/$n.conf"; done
if [ "$ZT_RUN_SERVERS" = "1" ]; then
  iperf3 -s -D
  socat UDP4-RECVFROM:7,fork EXEC:cat &
  socat TCP4-LISTEN:7,fork,reuseaddr EXEC:cat &
  mkdir -p /srv/www && echo "hello from the peer" > /srv/www/index.html
  (cd /srv/www && python3 -m http.server 8080 >/dev/null 2>&1 &)
fi
exec /usr/sbin/zerotier-one "$d"
