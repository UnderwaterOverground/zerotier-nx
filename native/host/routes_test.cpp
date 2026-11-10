// Tests for the socket layer's tunnel-address check (make routes-test).
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>

#include "vsock.hpp"

using ztnx::VSock;

static bool Routed(const char *ip) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &a.sin_addr);
    return VSock::IsTunnel(reinterpret_cast<sockaddr *>(&a));
}

static ZtnxPrefix V4(const char *ip, uint8_t len) {
    ZtnxPrefix p{};
    p.family = 4;
    p.len = len;
    inet_pton(AF_INET, ip, p.ip);
    return p;
}

int main() {
    // Nothing configured: nothing goes through the tunnel.
    assert(!Routed("10.7.0.1") && !Routed("192.168.1.10"));
    // Our own /32, a peer's /32 and its subnets.
    const ZtnxPrefix routes[] = {V4("10.7.0.2", 32), V4("10.7.0.1", 32), V4("10.123.0.0", 24), V4("192.168.1.0", 24)};
    VSock::SetRoutes(routes, 4);
    assert(Routed("10.7.0.2") && Routed("10.7.0.1") && Routed("10.123.0.9") && Routed("192.168.1.10"));
    assert(!Routed("10.7.0.9") && !Routed("10.124.0.1") && !Routed("8.8.8.8"));
    // At home on 192.168.1.0/24: that network is reached directly, as any
    // on-link route would be; the rest still go through the tunnel.
    VSock::SetLocalNet(ntohl(inet_addr("192.168.1.50")), 24);
    assert(!Routed("192.168.1.10") && Routed("10.123.0.9") && Routed("10.7.0.1"));
    // A LAN inside a tunnel route only takes its own addresses away.
    VSock::SetLocalNet(ntohl(inet_addr("10.123.0.50")), 25);
    assert(!Routed("10.123.0.9") && Routed("10.123.0.200") && Routed("192.168.1.10"));
    // Offline: every route is used.
    VSock::SetLocalNet(0, 32);
    assert(Routed("192.168.1.10") && Routed("10.123.0.9"));
    // A default route takes everything but the LAN and special addresses.
    const ZtnxPrefix all[] = {V4("10.7.0.2", 32), V4("0.0.0.0", 0)};
    VSock::SetRoutes(all, 2);
    VSock::SetLocalNet(ntohl(inet_addr("192.168.1.50")), 24);
    assert(Routed("8.8.8.8") && Routed("10.7.0.1") && !Routed("192.168.1.10"));
    assert(!Routed("127.0.0.1") && !Routed("0.0.0.0") && !Routed("224.0.0.251") && !Routed("255.255.255.255") && !Routed("169.254.3.4"));
    // The test knob sends the LAN through the tunnel too.
    VSock::SetTunnelLan(true);
    assert(Routed("192.168.1.10") && !Routed("127.0.0.1"));
    VSock::SetTunnelLan(false);
    assert(!Routed("192.168.1.10"));
    VSock::SetRoutes(nullptr, 0);
    assert(!Routed("8.8.8.8") && !Routed("10.7.0.1"));

    // Stand-ins: only private addresses get one, keeping the last two numbers.
    auto ip = [](const char *s) { return ntohl(inet_addr(s)); };
    assert(VSock::AliasFor(ip("10.253.0.1")) == ip("100.127.0.1"));
    assert(VSock::AliasFor(ip("192.168.1.50")) == ip("100.127.1.50"));
    assert(VSock::AliasFor(ip("172.20.3.4")) == ip("100.127.3.4"));
    assert(!VSock::AliasFor(ip("100.101.102.103")) && !VSock::AliasFor(ip("8.8.8.8")) && !VSock::AliasFor(ip("172.32.0.1")));
    assert(!VSock::AliasFor(ip("10.1.0.0")) && !VSock::AliasFor(ip("10.1.255.255")));
    // A stand-in goes through the tunnel even when its peer is on our LAN,
    // and translates both ways.
    const ZtnxPrefix peer[] = {V4("10.7.0.2", 32), V4("192.168.1.10", 32)};
    VSock::SetRoutes(peer, 2);
    const VSock::Alias aliases[] = {{ip("100.127.1.10"), ip("192.168.1.10")}};
    VSock::SetAliases(aliases, 1);
    VSock::SetLocalNet(ip("192.168.1.50"), 24);
    assert(Routed("100.127.1.10") && !Routed("100.127.1.11") && !Routed("192.168.1.10"));
    uint32_t a = ip("100.127.1.10");
    assert(VSock::ToReal(&a) && a == ip("192.168.1.10") && VSock::ToAlias(&a) && a == ip("100.127.1.10"));
    a = ip("10.7.0.2");
    assert(!VSock::ToReal(&a) && !VSock::ToAlias(&a) && a == ip("10.7.0.2"));
    // On a network that uses 100.127.0.0/16 itself, its hosts win.
    VSock::SetLocalNet(ip("100.127.0.5"), 16);
    a = ip("100.127.1.10");
    assert(!Routed("100.127.1.10") && !VSock::ToReal(&a));
    a = ip("192.168.1.10");
    assert(!VSock::ToAlias(&a));
    VSock::SetAliases(nullptr, 0);
    VSock::SetLocalNet(0, 32);
    VSock::SetRoutes(nullptr, 0);
    std::puts("routes-test: ok");
}
