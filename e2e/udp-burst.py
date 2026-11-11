#!/usr/bin/env python3
"""Sends a burst of large datagrams to a UDP echo server and counts the
echoes. Each one is too big for a single ZeroTier datagram, so every echo
comes back as two fragments that the receiver has to put together while
others are arriving.

  udp-burst.py <ip> <count> <size>      prints how many came back intact
"""
import socket
import sys
import time

ip, count, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
# First one small datagram until it comes back: the peer's MAC has to be
# found before a burst can get through (only one packet waits for it).
for attempt in range(30):
    s.sendto(b"warm-up", (ip, 7))
    try:
        if s.recvfrom(4096)[0] == b"warm-up":
            break
    except socket.timeout:
        pass
else:
    print("no answer to the warm-up datagram", file=sys.stderr)
    print(0)
    sys.exit(1)
s.settimeout(0.2)
sent = {}
for i in range(count):
    body = (b"%06d" % i) + bytes((i + j) & 0xFF for j in range(size - 6))
    sent[body[:6]] = body
    s.sendto(body, (ip, 7))
    time.sleep(0.002)
good = 0
deadline = time.time() + 4
while sent and time.time() < deadline:
    try:
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        continue
    if sent.pop(data[:6], None) == data:
        good += 1
print(good)
