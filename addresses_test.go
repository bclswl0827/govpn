package govpn

import (
	"net/netip"
	"slices"
	"testing"
)

func TestUpdateAddressesPreservesForwardAliases(t *testing.T) {
	old := netip.MustParsePrefix("192.0.2.2/32")
	next := netip.MustParsePrefix("192.0.2.3/32")
	alias := netip.MustParseAddr("198.51.100.9")
	session, err := NewSession([]netip.Prefix{old}, 1280, testPacketDevice{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	// Include forwards on both a protocol address and a separate alias.
	for _, address := range []netip.Addr{old.Addr(), alias} {
		acquired, err := session.acquireForwardAlias(address)
		if err != nil || !acquired {
			t.Fatalf("acquire %s: %v, %v", address, acquired, err)
		}
	}
	if err := session.UpdateAddresses([]netip.Prefix{next}); err != nil {
		t.Fatal(err)
	}
	for _, address := range []netip.Prefix{old, next, netip.PrefixFrom(alias, 32)} {
		if !slices.Contains(session.Addresses(), address) {
			t.Fatalf("lost %s: %v", address, session.Addresses())
		}
	}
	session.releaseForwardAlias(old.Addr())
	if slices.Contains(session.Addresses(), old) {
		t.Fatal("revoked alias was not removed")
	}
	// Promote an alias to a protocol address; releasing its last forward must keep it.
	assigned := netip.PrefixFrom(alias, 32)
	if err := session.UpdateAddresses([]netip.Prefix{next, assigned}); err != nil {
		t.Fatal(err)
	}
	session.releaseForwardAlias(alias)
	if !slices.Contains(session.Addresses(), assigned) {
		t.Fatal("forward release removed protocol address")
	}
	before := session.Addresses()
	if err := session.UpdateAddresses([]netip.Prefix{next, next}); err == nil {
		t.Fatal("accepted duplicate addresses")
	}
	if !slices.Equal(before, session.Addresses()) {
		t.Fatal("invalid update mutated addresses")
	}
	if err := session.UpdateAddresses(nil); err != nil {
		t.Fatal(err)
	}
	if len(session.Addresses()) != 0 {
		t.Fatal("address revocation did not clear addresses")
	}
	session.Close()
	if err := session.UpdateAddresses([]netip.Prefix{next}); err == nil {
		t.Fatal("updated closed Session")
	}
}
