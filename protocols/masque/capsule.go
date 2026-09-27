package masque

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	capsuleDatagram  = 0
	capsuleAssign    = 1
	capsuleRequest   = 2
	capsuleRoutes    = 3
	maxCapsuleLength = 1 << 20
)

type assignedAddress struct {
	id     uint64
	prefix netip.Prefix
}

type addressRange struct {
	start, end netip.Addr
	protocol   byte
}

func readVarint(r io.ByteReader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << (first >> 6)
	value := uint64(first & 63)
	for i := 1; i < n; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, io.ErrUnexpectedEOF
		}
		value = value<<8 | uint64(b)
	}
	return value, nil
}

func appendVarint(p []byte, value uint64) []byte {
	n, tag := 1, byte(0)
	switch {
	case value >= 1<<30:
		n, tag = 8, 192
	case value >= 1<<14:
		n, tag = 4, 128
	case value >= 1<<6:
		n, tag = 2, 64
	}
	start := len(p)
	for i := n - 1; i >= 0; i-- {
		p = append(p, byte(value>>(8*i)))
	}
	p[start] |= tag
	return p
}

func readCapsule(r *bufio.Reader) (uint64, []byte, error) {
	kind, err := readVarint(r)
	if err != nil {
		return 0, nil, err
	}
	n, err := readVarint(r)
	if err != nil {
		return 0, nil, err
	}
	if n > maxCapsuleLength {
		return 0, nil, errors.New("masque: capsule exceeds 1 MiB")
	}
	if kind > capsuleRoutes {
		_, err = io.CopyN(io.Discard, r, int64(n))
		return kind, nil, err
	}
	p := make([]byte, int(n))
	_, err = io.ReadFull(r, p)
	return kind, p, err
}

func writeCapsule(w io.Writer, kind uint64, p []byte) error {
	frame := appendVarint(nil, kind)
	frame = appendVarint(frame, uint64(len(p)))
	frame = append(frame, p...)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func readAddress(r *bytes.Reader, n int) (netip.Addr, error) {
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return netip.Addr{}, err
	}
	a, _ := netip.AddrFromSlice(p)
	if a.Is4In6() {
		return netip.Addr{}, errors.New("masque: IPv4-mapped IPv6 address")
	}
	return a, nil
}

func addressSize(r *bytes.Reader) (int, error) {
	v, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch v {
	case 4:
		return 4, nil
	case 6:
		return 16, nil
	default:
		return 0, fmt.Errorf("masque: invalid IP version %d", v)
	}
}

func parseAddresses(p []byte) ([]assignedAddress, error) {
	r := bytes.NewReader(p)
	var addresses []assignedAddress
	for r.Len() != 0 {
		id, err := readVarint(r)
		if err != nil {
			return nil, err
		}
		n, err := addressSize(r)
		if err != nil {
			return nil, err
		}
		a, err := readAddress(r, n)
		if err != nil {
			return nil, err
		}
		bits, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		prefix := netip.PrefixFrom(a, int(bits))
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return nil, errors.New("masque: invalid address prefix")
		}
		addresses = append(addresses, assignedAddress{id, prefix})
	}
	return addresses, nil
}

func encodeAddresses(addresses []assignedAddress) []byte {
	var p []byte
	for _, a := range addresses {
		p = appendVarint(p, a.id)
		if a.prefix.Addr().Is4() {
			p = append(p, 4)
		} else {
			p = append(p, 6)
		}
		p = append(p, a.prefix.Addr().AsSlice()...)
		p = append(p, byte(a.prefix.Bits()))
	}
	return p
}

func parseRoutes(p []byte) ([]addressRange, error) {
	r := bytes.NewReader(p)
	var routes []addressRange
	for r.Len() != 0 {
		n, err := addressSize(r)
		if err != nil {
			return nil, err
		}
		start, err := readAddress(r, n)
		if err != nil {
			return nil, err
		}
		end, err := readAddress(r, n)
		if err != nil {
			return nil, err
		}
		protocol, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if start.Compare(end) > 0 {
			return nil, errors.New("masque: reversed route range")
		}
		if len(routes) > 0 {
			previous := routes[len(routes)-1]
			if previous.start.BitLen() > start.BitLen() || (previous.start.BitLen() == start.BitLen() &&
				(previous.protocol > protocol || (previous.protocol == protocol && previous.end.Compare(start) >= 0))) {
				return nil, errors.New("masque: unordered or overlapping routes")
			}
		}
		routes = append(routes, addressRange{start, end, protocol})
	}
	return routes, nil
}

func encodeRoutes(prefixes []netip.Prefix) []byte {
	var p []byte
	for _, prefix := range prefixes {
		start := prefix.Masked().Addr()
		end := append([]byte(nil), start.AsSlice()...)
		for bit := prefix.Bits(); bit < start.BitLen(); bit++ {
			end[bit/8] |= 1 << (7 - bit%8)
		}
		if start.Is4() {
			p = append(p, 4)
		} else {
			p = append(p, 6)
		}
		p = append(p, start.AsSlice()...)
		p = append(p, end...)
		p = append(p, 0)
	}
	return p
}
