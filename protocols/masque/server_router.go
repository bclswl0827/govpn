package masque

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/bclswl0827/govpn/internal/packet"
)

type serverPeer struct {
	tunnel   *tunnel
	queue    *packet.Device
	assigned []assignedAddress
	allowed  []addressRange
	ready    atomic.Bool
	order    uint64
}

func (s *serverTransport) lookup(destination netip.Addr, protocol uint8) *serverPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *serverPeer
	for p := range s.peers {
		if !p.ready.Load() {
			continue
		}
		if containsAddress(p.assigned, destination) {
			return p
		}
	}
	for _, local := range s.local {
		if local.Addr() == destination {
			return nil
		}
	}
	for p := range s.peers {
		if !p.ready.Load() {
			continue
		}
		p.tunnel.stateMu.RLock()
		match := containsRoute(p.tunnel.routes, destination, protocol)
		p.tunnel.stateMu.RUnlock()
		if match && (found == nil || p.order > found.order) {
			found = p
		}
	}
	return found
}
func (s *serverTransport) release(p *serverPeer) {
	p.ready.Store(false)
	s.mu.Lock()
	delete(s.peers, p)
	s.mu.Unlock()
	if p.queue != nil {
		p.queue.Close()
	}
	for _, a := range p.assigned {
		for _, pool := range s.pools {
			if pool.prefix.Contains(a.prefix.Addr()) {
				pool.release(a.prefix.Addr())
			}
		}
	}
}
func (s *serverTransport) reply(ctx context.Context, p []byte, kind packetError, origin *serverPeer, mtu int) error {
	reply := icmpError(p, kind, s.local, mtu)
	if reply == nil {
		return nil
	}
	if origin != nil {
		origin.queue.TryInject(reply)
		return nil
	}
	_, destination, _ := packetAddresses(reply)
	protocol, _ := packetProtocol(reply)
	if target := s.lookup(destination, protocol); target != nil {
		target.queue.TryInject(reply)
		return nil
	}
	if s.forwardPacket != nil {
		local := false
		for _, address := range s.local {
			local = local || address.Addr() == destination
		}
		if !local {
			return s.forwardPacket(ctx, reply)
		}
	}
	return s.device.WritePacket(ctx, reply)
}
func (s *serverTransport) inbound(ctx context.Context, origin *serverPeer, p []byte) error {
	source, destination, valid := packetAddresses(p)
	protocol, ok := packetProtocol(p)
	if !valid || !ok {
		return nil
	}
	origin.tunnel.stateMu.RLock()
	peerRoutes := append([]addressRange(nil), origin.tunnel.routes...)
	origin.tunnel.stateMu.RUnlock()
	for i := range peerRoutes {
		peerRoutes[i].protocol = 0
	}
	if !containsAddress(origin.assigned, source) && !containsRoute(peerRoutes, source, 0) {
		return s.reply(ctx, p, sourcePolicy, origin, 0)
	}
	if destination.IsLinkLocalUnicast() || destination.IsMulticast() {
		return nil
	}
	if !containsRoute(origin.allowed, destination, protocol) {
		return s.reply(ctx, p, noRoute, origin, 0)
	}
	target := s.lookup(destination, protocol)
	if target != nil {
		if protocol != 1 && protocol != 58 && !containsRoute(target.allowed, source, protocol) {
			return s.reply(ctx, p, noRoute, origin, 0)
		}
		p = append([]byte(nil), p...)
		if !decrementHopLimit(p) {
			return s.reply(ctx, p, hopLimitExceeded, origin, 0)
		}
		// Isolate peers: a stalled peer must not block another peer's receive loop.
		target.queue.TryInject(p)
		return nil
	}
	for _, a := range s.local {
		if a.Addr() == destination {
			return s.device.WritePacket(ctx, p)
		}
	}
	for _, pool := range s.pools {
		if pool.prefix.Contains(destination) {
			return s.reply(ctx, p, addressUnreachable, origin, 0)
		}
	}
	if s.forwardPacket != nil {
		return s.forwardPacket(ctx, append([]byte(nil), p...))
	}
	return s.device.WritePacket(ctx, p)
}
func (s *serverTransport) outbound(ctx context.Context, p []byte, forwarded bool) error {
	source, destination, valid := packetAddresses(p)
	protocol, ok := packetProtocol(p)
	if !valid || !ok {
		return errors.New("masque: invalid IP packet")
	}
	target := s.lookup(destination, protocol)
	if target == nil || protocol != 1 && protocol != 58 && !containsRoute(target.allowed, source, protocol) {
		return s.reply(ctx, p, noRoute, nil, 0)
	}
	if forwarded {
		p = append([]byte(nil), p...)
		if !decrementHopLimit(p) {
			return s.reply(ctx, p, hopLimitExceeded, nil, 0)
		}
	}
	target.queue.TryInject(p)
	return nil
}
func (s *serverTransport) dispatch() {
	for {
		p, err := s.device.ReadPacket(s.ctx)
		if err != nil {
			return
		}
		_ = s.outbound(s.ctx, p, false)
	}
}

// WritePacket routes a packet from an external network to a connected client.
// It copies the packet and decrements its hop limit. No host routes are changed.
func (s *Server) WritePacket(ctx context.Context, p []byte) error {
	s.mu.Lock()
	t := s.transport
	s.mu.Unlock()
	if t == nil || t.ctx.Err() != nil {
		return net.ErrClosed
	}
	return t.outbound(ctx, p, true)
}
