package masque

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"testing"
)

func TestAddressAssignWire(t *testing.T) {
	// RFC 9484: request ID 0, IPv4, 192.0.2.2/32.
	wire := []byte{1, 7, 0, 4, 192, 0, 2, 2, 32}
	kind, payload, err := readCapsule(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil || kind != capsuleAssign {
		t.Fatalf("read capsule: %d, %v", kind, err)
	}
	addresses, err := parseAddresses(payload)
	if err != nil || len(addresses) != 1 || addresses[0].id != 0 || addresses[0].prefix.String() != "192.0.2.2/32" {
		t.Fatalf("decode assignment: %v, %v", addresses, err)
	}
	var output bytes.Buffer
	if err := writeCapsule(&output, capsuleAssign, encodeAddresses(addresses)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), wire) {
		t.Fatalf("wire = %x, want %x", output.Bytes(), wire)
	}
}

func TestVarintBoundaries(t *testing.T) {
	for _, value := range []uint64{0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1} {
		wire := appendVarint(nil, value)
		got, err := readVarint(bytes.NewReader(wire))
		if err != nil || got != value {
			t.Fatalf("%d: got %d, %v", value, got, err)
		}
		if len(wire) > 1 {
			if _, err := readVarint(bytes.NewReader(wire[:len(wire)-1])); err == nil {
				t.Fatalf("accepted truncated varint %x", wire)
			}
		}
	}
}

func TestCapsuleBoundsAndUnknownTypes(t *testing.T) {
	for _, wire := range [][]byte{
		{0, 2, 0}, // Truncated datagram payload.
		appendVarint([]byte{0}, maxCapsuleLength+1),
	} {
		if _, _, err := readCapsule(bufio.NewReader(bytes.NewReader(wire))); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
	// An unknown capsule must be skipped without consuming the following one.
	r := bufio.NewReader(bytes.NewReader([]byte{42, 3, 1, 2, 3, 0, 1, 0}))
	if kind, _, err := readCapsule(r); err != nil || kind != 42 {
		t.Fatalf("unknown: %d, %v", kind, err)
	}
	if kind, p, err := readCapsule(r); err != nil || kind != 0 || !bytes.Equal(p, []byte{0}) {
		t.Fatalf("next: %d, %x, %v", kind, p, err)
	}
	if _, _, err := readCapsule(r); err != io.EOF {
		t.Fatalf("end: %v", err)
	}
}

func TestMalformedControlCapsules(t *testing.T) {
	for _, payload := range [][]byte{
		{0, 5}, // Unknown address family.
		{0, 4, 192, 0, 2},
		{0, 4, 192, 0, 2, 1, 33},
		{0, 4, 192, 0, 2, 1, 24}, // Host bits in an assigned prefix.
	} {
		if _, err := parseAddresses(payload); err == nil {
			t.Fatalf("accepted address %x", payload)
		}
	}
	for _, payload := range [][]byte{
		{4, 192, 0, 2, 2, 192, 0, 2, 1, 0}, // Reversed range.
		{6, 0},
		append(encodeRoutes([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}), encodeRoutes([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/25")})...),
	} {
		if _, err := parseRoutes(payload); err == nil {
			t.Fatalf("accepted route %x", payload)
		}
	}
}

func TestDualStackRoutes(t *testing.T) {
	payload := encodeRoutes([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/64")})
	routes, err := parseRoutes(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].end.String() != "192.0.2.255" || routes[1].end.String() != "2001:db8::ffff:ffff:ffff:ffff" {
		t.Fatalf("routes: %v", routes)
	}
}
