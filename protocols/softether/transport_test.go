package softether

import (
	"net/netip"
	"testing"
)

func TestNeighborLearningIsBoundedToLocalNextHops(t *testing.T) {
	gateway := netip.MustParseAddr("192.0.2.1")
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	transport := newTransport(nil, nil, nil, [6]byte{}, netip.MustParsePrefix("10.0.0.2/16"), gateway, mac, nil)
	for _, address := range []string{"203.0.113.7", "0.0.0.0", "224.0.0.1", "2001:db8::1"} {
		transport.learnNeighbor(netip.MustParseAddr(address), mac)
	}
	if len(transport.neighbors) != 1 {
		t.Fatalf("learned non-local hosts: %v", transport.neighbors)
	}
	address := netip.MustParseAddr("10.0.1.1")
	for range 512 {
		transport.learnNeighbor(address, mac)
		address = address.Next()
	}
	if len(transport.neighbors) > 256 {
		t.Fatalf("neighbor cache grew to %d entries", len(transport.neighbors))
	}
	if got, exists := transport.neighbors[gateway]; !exists || got != mac {
		t.Fatalf("gateway lost after neighbor churn: %v, %t", got, exists)
	}
	newMAC := [6]byte{2, 0, 0, 0, 0, 2}
	transport.learnNeighbor(gateway, newMAC)
	if got := transport.neighbors[gateway]; got != newMAC {
		t.Fatalf("gateway MAC was not refreshed: %v", got)
	}
}
