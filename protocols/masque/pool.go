package masque

import (
	"errors"
	"net/netip"
	"sync"
)

type addressPool struct {
	mu                 sync.Mutex
	prefix             netip.Prefix
	server, last, next netip.Addr
	used               map[netip.Addr]bool
}

func newAddressPool(address netip.Prefix) (*addressPool, error) {
	if !address.IsValid() || address.Addr().Is4In6() || address.Addr().Zone() != "" || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
		return nil, errors.New("masque: invalid server address")
	}
	p := &addressPool{prefix: address.Masked(), server: address.Addr(), last: prefixEnd(address), next: address.Masked().Addr(), used: make(map[netip.Addr]bool)}
	a, ok := p.allocate()
	if !ok {
		return nil, errors.New("masque: pool has no usable client addresses")
	}
	p.release(a)
	p.next = p.prefix.Addr()
	return p, nil
}
func (p *addressPool) allocate() (netip.Addr, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// At most the allocated addresses plus network, broadcast and server can
	// be skipped. Never iterate an entire IPv6 prefix on exhaustion.
	for attempts := 0; attempts < len(p.used)+4; attempts++ {
		a := p.next
		if a == p.last {
			p.next = p.prefix.Addr()
		} else {
			p.next = a.Next()
		}
		if a == p.server || a == p.prefix.Addr() || a.Is4() && a == p.last || p.used[a] {
			continue
		}
		p.used[a] = true
		return a, true
	}
	return netip.Addr{}, false
}
func (p *addressPool) release(a netip.Addr) { p.mu.Lock(); delete(p.used, a); p.mu.Unlock() }
