package ikev2

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
)

var errAddressPoolExhausted = errors.New("ikev2: address pool exhausted")

type addressPool struct {
	mu          sync.Mutex
	first, last uint32
	used        map[uint32]struct{}
}

func newAddressPool(network netip.Prefix, gateway netip.Addr) *addressPool {
	networkValue := binary.BigEndian.Uint32(network.Addr().AsSlice())
	mask := binary.BigEndian.Uint32(net.CIDRMask(network.Bits(), 32))
	broadcast := networkValue | ^mask
	first := binary.BigEndian.Uint32(gateway.AsSlice()) + 1
	return &addressPool{first: first, last: broadcast - 1, used: make(map[uint32]struct{})}
}

func (pool *addressPool) allocate() (net.IP, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for candidate := pool.first; candidate <= pool.last; candidate++ {
		if _, exists := pool.used[candidate]; exists {
			continue
		}
		pool.used[candidate] = struct{}{}
		var value [4]byte
		binary.BigEndian.PutUint32(value[:], candidate)
		return net.IPv4(value[0], value[1], value[2], value[3]), nil
	}
	return nil, errAddressPoolExhausted
}

func (pool *addressPool) release(address net.IP) {
	value := address.To4()
	if value == nil {
		return
	}
	pool.mu.Lock()
	delete(pool.used, binary.BigEndian.Uint32(value))
	pool.mu.Unlock()
}

func ipv4Key(address net.IP) uint32 {
	value := address.To4()
	if value == nil {
		return 0
	}
	return binary.BigEndian.Uint32(value)
}

func packetSource(packet []byte) net.IP {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	return net.IP(packet[12:16])
}

func packetDestination(packet []byte) net.IP {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	return net.IP(packet[16:20])
}
