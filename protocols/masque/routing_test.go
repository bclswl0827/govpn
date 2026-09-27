package masque

import (
	"context"
	"encoding/binary"
	"net/netip"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
)

func TestURITemplateScopes(t *testing.T) {
	for _, path := range []string{DefaultTemplate, "/ip{?target,ipproto}", "/ip?t={target}&p={ipproto}", "/ip?fixed=1{&target,ipproto}"} {
		t.Run(path, func(t *testing.T) {
			template, err := parseTemplate(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{"*", "192.0.2.0/24", "2001:db8::/64", "example.com"} {
				expanded := template.expand(target, 6)
				u, err := url.ParseRequestURI(expanded)
				if err != nil {
					t.Fatal(err)
				}
				scope, matched, err := template.match(u)
				if err != nil || !matched || scope.target != target || scope.protocol != 6 {
					t.Fatalf("%s: %+v matched=%v err=%v", expanded, scope, matched, err)
				}
			}
		})
	}
	for _, path := range []string{"//host/path", "/ip/{target", "/ip/{+target}", "/ip/{bad}", "/ip#fragment"} {
		if _, err := parseTemplate(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}
func TestAddressPoolExhaustionReleaseAndServerReservation(t *testing.T) {
	for _, prefix := range []string{"192.0.2.1/30", "2001:db8::1/126", "192.0.2.5/29"} {
		pool, err := newAddressPool(netip.MustParsePrefix(prefix))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[netip.Addr]bool{}
		var first netip.Addr
		for {
			a, ok := pool.allocate()
			if !ok {
				break
			}
			if a == pool.server || a == pool.prefix.Addr() || a.Is4() && a == pool.last || seen[a] {
				t.Fatalf("bad allocation %s", a)
			}
			seen[a] = true
			if !first.IsValid() {
				first = a
			}
			if len(seen) > 8 {
				t.Fatal("pool allocation did not stop")
			}
		}
		if !first.IsValid() {
			t.Fatal("no address allocated")
		}
		pool.release(first)
		a, ok := pool.allocate()
		if !ok || a != first {
			t.Fatalf("released address not reused: %s %v", a, ok)
		}
	}
}
func TestRouteNormalizationAndScope(t *testing.T) {
	routes, err := routesFromPrefixes([]netip.Prefix{netip.MustParsePrefix("192.0.2.128/25"), netip.MustParsePrefix("192.0.2.0/25"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("ranges=%v", routes)
	}
	decoded, err := parseRoutes(encodeRanges(routes))
	if err != nil || !reflect.DeepEqual(decoded, routes) {
		t.Fatalf("round trip: %v %v", decoded, err)
	}
	scoped := scopeRoutes(routes, []netip.Prefix{netip.MustParsePrefix("192.0.2.8/30")}, 17, []assignedAddress{{prefix: netip.MustParsePrefix("192.0.2.2/32")}})
	if len(scoped) != 1 || !containsRoute(scoped, netip.MustParseAddr("192.0.2.9"), 17) || containsRoute(scoped, netip.MustParseAddr("192.0.2.9"), 6) || containsRoute(scoped, netip.MustParseAddr("192.0.2.12"), 17) {
		t.Fatalf("scope=%v", scoped)
	}
}
func testIPv4(source, destination string, ttl byte) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = ttl, 17
	copy(p[12:16], netip.MustParseAddr(source).AsSlice())
	copy(p[16:20], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	return p
}
func TestServerPeerRoutingPolicyAndHopLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	device, _ := packet.New("test-router", 1280)
	defer device.Close()
	s := &serverTransport{device: device, local: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}, peers: make(map[*serverPeer]struct{})}
	all, _ := routesFromPrefixes([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	makePeer := func(address string) *serverPeer {
		q, _ := packet.New("test-peer", 1280)
		t.Cleanup(func() { q.Close() })
		p := &serverPeer{queue: q, assigned: []assignedAddress{{prefix: netip.MustParsePrefix(address + "/32")}}, allowed: all, tunnel: &tunnel{}}
		p.ready.Store(true)
		s.peers[p] = struct{}{}
		return p
	}
	a, b := makePeer("192.0.2.2"), makePeer("192.0.2.3")
	data := testIPv4("192.0.2.2", "192.0.2.3", 64)
	if err := s.inbound(ctx, a, data); err != nil {
		t.Fatal(err)
	}
	received, err := b.queue.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if received[8] != 63 || checksum(received[:20]) != 0 {
		t.Fatal("forwarding did not update hop limit/checksum")
	}
	for _, test := range []struct {
		packet     []byte
		kind, code byte
	}{
		{testIPv4("192.0.2.2", "192.0.2.3", 1), 11, 0},
		{testIPv4("198.51.100.9", "192.0.2.3", 64), 3, 13},
	} {
		if err := s.inbound(ctx, a, test.packet); err != nil {
			t.Fatal(err)
		}
		reply, err := a.queue.ReadPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if reply[20] != test.kind || reply[21] != test.code || checksum(reply[:20]) != 0 || checksum(reply[20:]) != 0 {
			t.Fatalf("invalid ICMP response: %x", reply)
		}
	}
	// A slow B cannot block delivery to A or the server dispatcher.
	for i := 0; i < 2048; i++ {
		if err := s.inbound(ctx, a, data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueryTemplateValidation(t *testing.T) {
	template, err := parseTemplate("/ip?fixed=a%20b{&target,ipproto}")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"/ip?fixed=a%20b&target=&ipproto=6",
		"/ip?fixed=a%20b&target=*&target=example.com",
		"/ip?fixed=a%20b&ipproto=256",
		"/ip?fixed=a%20b&target=%ZZ",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := template.match(u); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	u, _ := url.Parse("/ip?ipproto=17&target=example.com&fixed=a+b")
	scope, matched, err := template.match(u)
	if err != nil || !matched || scope.protocol != 17 || scope.target != "example.com" {
		t.Fatalf("scope=%+v matched=%v error=%v", scope, matched, err)
	}
	for _, raw := range []string{"/ip\t", "/ip?x=1&x=2", "/ip?x=%ZZ"} {
		if _, err := parseTemplate(raw); err == nil {
			t.Fatalf("accepted template %q", raw)
		}
	}
}

func TestProtocolScopeAllowsControlPackets(t *testing.T) {
	routes := []addressRange{{start: netip.MustParseAddr("192.0.2.0"), end: netip.MustParseAddr("192.0.2.255"), protocol: 6}}
	if !containsRoute(routes, netip.MustParseAddr("192.0.2.9"), 1) {
		t.Fatal("TCP scope blocked ICMP control packets")
	}
	if containsRoute(routes, netip.MustParseAddr("198.51.100.9"), 1) {
		t.Fatal("control packet escaped destination scope")
	}
}
