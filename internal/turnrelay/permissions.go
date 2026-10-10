package turnrelay

import (
	"net"
	"net/netip"
)

var blockedPeerRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// TURN must not become a route into the server's LAN or cloud metadata services.
// IPv6 peers are rejected because this relay allocates IPv4 sockets only.
func publicPeerPermission(_ net.Addr, peer net.IP) bool {
	ip, ok := netip.AddrFromSlice(peer)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blockedPeerRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
