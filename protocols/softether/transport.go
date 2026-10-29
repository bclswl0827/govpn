package softether

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
	transportutil "github.com/bclswl0827/govpn/internal/transport"
	protocol "github.com/bclswl0827/govpn/protocols/softether/internal"
)

type transport struct {
	conn        net.Conn
	device      *packet.Device
	stream      *protocol.FrameStream
	localMAC    [6]byte
	localIP     netip.Addr
	localPrefix netip.Prefix
	gateway     netip.Addr
	dhcpReply   func([]byte) ([]byte, netip.Addr, [6]byte, bool)
	neighborMu  sync.RWMutex
	neighbors   map[netip.Addr][6]byte
	once        sync.Once
	closed      chan struct{}
}

func newTransport(conn net.Conn, device *packet.Device, stream *protocol.FrameStream, localMAC [6]byte, localPrefix netip.Prefix, gateway netip.Addr, gatewayMAC [6]byte, dhcpReply func([]byte) ([]byte, netip.Addr, [6]byte, bool)) *transport {
	t := &transport{
		conn: conn, device: device, stream: stream, localMAC: localMAC, localIP: localPrefix.Addr(),
		localPrefix: localPrefix.Masked(), gateway: gateway, dhcpReply: dhcpReply,
		neighbors: make(map[netip.Addr][6]byte), closed: make(chan struct{}),
	}
	if gateway.IsValid() && gatewayMAC != ([6]byte{}) {
		t.neighbors[gateway] = gatewayMAC
	}
	return t
}

func (t *transport) Close() error {
	var err error
	t.once.Do(func() {
		close(t.closed)
		err = errors.Join(t.conn.Close(), t.device.Close())
	})
	return err
}

func (t *transport) run(done chan<- error) {
	errCh := make(chan error, 3)
	go func() {
		for {
			payload, err := t.device.ReadPacket(context.Background())
			if err == nil {
				remote := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				if destination, ok := protocol.IPDestination(payload); ok {
					nextHop := destination
					if t.gateway.IsValid() && !t.localPrefix.Contains(destination) {
						nextHop = t.gateway
					}
					t.neighborMu.RLock()
					if learned, exists := t.neighbors[nextHop]; exists {
						remote = learned
					}
					t.neighborMu.RUnlock()
				}
				err = t.stream.WriteFrames(protocol.WrapIPv4(payload, t.localMAC, remote))
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := t.stream.WriteKeepAlive(); err != nil {
					errCh <- err
					return
				}
			case <-t.closed:
				return
			}
		}
	}()
	go func() {
		for {
			frames, err := t.stream.ReadFrames()
			if err != nil {
				errCh <- err
				return
			}
			for _, frame := range frames {
				if t.dhcpReply != nil {
					if reply, address, mac, ok := t.dhcpReply(frame); ok {
						t.learnNeighbor(address, mac)
						if err := t.stream.WriteFrames(reply); err != nil {
							errCh <- err
							return
						}
						continue
					}
				}
				if source, mac, ok := protocol.FrameSource(frame); ok && !source.IsUnspecified() {
					t.learnNeighbor(source, mac)
				}
				if reply, ok := protocol.ARPReply(frame, t.localMAC, t.localIP); ok {
					if err := t.stream.WriteFrames(reply); err != nil {
						errCh <- err
						return
					}
					continue
				}
				payload, ok := protocol.UnwrapIP(frame)
				if ok {
					if _, err := t.device.TryWritePacket(payload); err != nil {
						errCh <- err
						return
					}
				}
			}
		}
	}()
	err := <-errCh
	_ = t.Close()
	done <- transportutil.NormalizeError(err)
}

func (t *transport) learnNeighbor(address netip.Addr, mac [6]byte) {
	// Remote Internet hosts share the gateway's MAC. Remember only next hops
	// we can actually send to on this Ethernet segment.
	if !address.Is4() || address.IsUnspecified() || address.IsMulticast() ||
		(address != t.gateway && !t.localPrefix.Contains(address)) {
		return
	}
	const maxNeighbors = 256
	t.neighborMu.Lock()
	defer t.neighborMu.Unlock()
	if _, exists := t.neighbors[address]; !exists && len(t.neighbors) >= maxNeighbors {
		for candidate := range t.neighbors {
			if candidate != t.gateway {
				delete(t.neighbors, candidate)
				break
			}
		}
	}
	t.neighbors[address] = mac
}
