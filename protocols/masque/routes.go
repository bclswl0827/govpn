package masque

import (
	"errors"
	"net/netip"
	"slices"
)

// Route describes an inclusive destination range. Protocol zero matches all IP protocols.
type Route struct {
	Start, End netip.Addr
	Protocol   uint8
}

func prefixEnd(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for bit := p.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 1 << uint(7-bit%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func routesFromPrefixes(prefixes []netip.Prefix) ([]addressRange, error) {
	var ranges []addressRange
	for _, p := range prefixes {
		if !p.IsValid() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return nil, errors.New("masque: invalid advertised prefix")
		}
		ranges = append(ranges, addressRange{start: p.Masked().Addr(), end: prefixEnd(p)})
	}
	slices.SortFunc(ranges, func(a, b addressRange) int { return a.start.Compare(b.start) })
	var merged []addressRange
	for _, r := range ranges {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if last.start.BitLen() == r.start.BitLen() && (r.start.Compare(last.end) <= 0 || last.end.Next() == r.start) {
				if r.end.Compare(last.end) > 0 {
					last.end = r.end
				}
				continue
			}
		}
		merged = append(merged, r)
	}
	return merged, nil
}
func containsRoute(routes []addressRange, a netip.Addr, proto uint8) bool {
	return slices.ContainsFunc(routes, func(r addressRange) bool {
		return a.BitLen() == r.start.BitLen() && r.start.Compare(a) <= 0 && a.Compare(r.end) <= 0 && (r.protocol == 0 || proto == r.protocol || proto == 1 || proto == 58)
	})
}
func containsAddress(addresses []assignedAddress, a netip.Addr) bool {
	return slices.ContainsFunc(addresses, func(x assignedAddress) bool { return x.prefix.Contains(a) })
}
func encodeRanges(routes []addressRange) []byte {
	var p []byte
	for _, r := range routes {
		if r.start.Is4() {
			p = append(p, 4)
		} else {
			p = append(p, 6)
		}
		p = append(p, r.start.AsSlice()...)
		p = append(p, r.end.AsSlice()...)
		p = append(p, r.protocol)
	}
	return p
}
func publicRoutes(routes []addressRange) []Route {
	out := make([]Route, len(routes))
	for i, r := range routes {
		out[i] = Route{r.start, r.end, r.protocol}
	}
	return out
}
func scopeRoutes(routes []addressRange, targets []netip.Prefix, protocol uint8, addresses []assignedAddress) []addressRange {
	var out []addressRange
	for _, r := range routes {
		if !slices.ContainsFunc(addresses, func(a assignedAddress) bool { return a.prefix.Addr().BitLen() == r.start.BitLen() }) {
			continue
		}
		if len(targets) == 0 {
			r.protocol = protocol
			out = append(out, r)
			continue
		}
		for _, target := range targets {
			if target.Addr().BitLen() != r.start.BitLen() {
				continue
			}
			low, high := target.Masked().Addr(), prefixEnd(target)
			if low.Compare(r.start) < 0 {
				low = r.start
			}
			if high.Compare(r.end) > 0 {
				high = r.end
			}
			if low.Compare(high) <= 0 {
				out = append(out, addressRange{low, high, protocol})
			}
		}
	}
	slices.SortFunc(out, func(a, b addressRange) int { return a.start.Compare(b.start) })
	// DNS may return duplicates; normalize intersections before advertising.
	var result []addressRange
	for _, r := range out {
		if len(result) > 0 {
			last := &result[len(result)-1]
			if last.start.BitLen() == r.start.BitLen() && r.start.Compare(last.end) <= 0 {
				if r.end.Compare(last.end) > 0 {
					last.end = r.end
				}
				continue
			}
		}
		result = append(result, r)
	}
	return result
}
