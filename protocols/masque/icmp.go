package masque

import (
	"encoding/binary"
	"net/netip"
)

type packetError uint8

const (
	noRoute packetError = iota
	sourcePolicy
	addressUnreachable
	hopLimitExceeded
	packetTooBig
)

func packetProtocol(p []byte) (uint8, bool) {
	_, _, ok := packetAddresses(p)
	if !ok {
		return 0, false
	}
	if p[0]>>4 == 4 {
		return p[9], true
	}
	next, offset := p[6], 40
	for steps := 0; steps < 16; steps++ {
		switch next {
		case 0, 43, 60:
			if offset+2 > len(p) {
				return 0, false
			}
			size := (int(p[offset+1]) + 1) * 8
			if offset+size > len(p) {
				return 0, false
			}
			next, offset = p[offset], offset+size
		case 44:
			if offset+8 > len(p) {
				return 0, false
			}
			next, offset = p[offset], offset+8
		case 51:
			if offset+2 > len(p) {
				return 0, false
			}
			size := (int(p[offset+1]) + 2) * 4
			if offset+size > len(p) {
				return 0, false
			}
			next, offset = p[offset], offset+size
		default:
			return next, true
		}
	}
	return 0, false
}
func checksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func decrementHopLimit(p []byte) bool {
	if p[0]>>4 == 4 {
		if p[8] <= 1 {
			return false
		}
		p[8]--
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:12], checksum(p[:int(p[0]&15)*4]))
		return true
	}
	if p[7] <= 1 {
		return false
	}
	p[7]--
	return true
}
func icmpError(p []byte, kind packetError, locals []netip.Prefix, mtu int) []byte {
	src, dst, ok := packetAddresses(p)
	if !ok || src.IsUnspecified() || src.IsMulticast() || dst.IsMulticast() {
		return nil
	}
	var local netip.Addr
	for _, a := range locals {
		if a.Addr().BitLen() == src.BitLen() {
			local = a.Addr()
			break
		}
	}
	if !local.IsValid() {
		return nil
	}
	proto, ok := packetProtocol(p)
	if !ok {
		return nil
	}
	// Never send errors in response to errors. For extension-bearing IPv6 ICMP,
	// conservatively suppress replies rather than risk an ICMP error loop.
	if src.Is4() {
		off := int(p[0]&15) * 4
		if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			return nil
		}
		if proto == 1 && (off >= len(p) || p[off] != 0 && p[off] != 8) {
			return nil
		}
	} else if proto == 58 && (p[6] != 58 || len(p) <= 40 || p[40] < 128) {
		return nil
	}
	if src.Is4() {
		quote := p[:min(len(p), 548)]
		out := make([]byte, 28+len(quote))
		out[0] = 0x45
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[8], out[9] = 64, 1
		copy(out[12:16], local.AsSlice())
		copy(out[16:20], src.AsSlice())
		out[20] = 3
		switch kind {
		case sourcePolicy:
			out[21] = 13
		case addressUnreachable:
			out[21] = 1
		case hopLimitExceeded:
			out[20] = 11
		case packetTooBig:
			out[21] = 4
			binary.BigEndian.PutUint16(out[26:28], uint16(mtu))
		}
		copy(out[28:], quote)
		binary.BigEndian.PutUint16(out[22:24], checksum(out[20:]))
		binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
		return out
	}
	quote := p[:min(len(p), 1232)]
	out := make([]byte, 48+len(quote))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	out[6], out[7] = 58, 64
	copy(out[8:24], local.AsSlice())
	copy(out[24:40], src.AsSlice())
	out[40] = 1
	switch kind {
	case sourcePolicy:
		out[41] = 5
	case addressUnreachable:
		out[41] = 3
	case hopLimitExceeded:
		out[40] = 3
	case packetTooBig:
		out[40] = 2
		binary.BigEndian.PutUint32(out[44:48], uint32(mtu))
	}
	copy(out[48:], quote)
	pseudo := append([]byte(nil), out[8:40]...)
	pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(out)-40))
	pseudo = append(pseudo, 0, 0, 0, 58)
	pseudo = append(pseudo, out[40:]...)
	binary.BigEndian.PutUint16(out[42:44], checksum(pseudo))
	return out
}
