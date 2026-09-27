package masque

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sync"

	"github.com/quic-go/quic-go"
)

// A tunnel has one capsule reader. All control and packet writes share a lock.
type tunnel struct {
	conn             io.ReadWriteCloser
	reader           *bufio.Reader
	writeMu          sync.Mutex
	addresses        []assignedAddress
	routes           []addressRange
	server           bool
	stateMu          sync.RWMutex
	routesAdvertised bool
	advertised       []addressRange
	onAssign         func([]assignedAddress) error
	onRoutes         func([]addressRange) error
	onPacket         func(context.Context, []byte) error
	filterOutbound   func(context.Context, []byte) (bool, error)
	onTooBig         func(context.Context, []byte, int) error
}

func (t *tunnel) write(kind uint64, payload []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return writeCapsule(t.conn, kind, payload)
}

func (t *tunnel) control(kind uint64, payload []byte) error {
	switch kind {
	case capsuleAssign:
		addresses, err := parseAddresses(payload)
		if err != nil {
			return err
		}
		if t.server {
			return nil
		}
		if t.onAssign != nil {
			return t.onAssign(addresses)
		}
		t.stateMu.Lock()
		changed := !slices.Equal(localAddresses(addresses), localAddresses(t.addresses))
		t.stateMu.Unlock()
		if changed {
			return errors.New("masque: address assignment changed; no update handler")
		}

	case capsuleRequest:
		requests, err := parseAddresses(payload)
		if err != nil {
			return err
		}
		if len(requests) == 0 {
			return errors.New("masque: empty address request")
		}
		used := make(map[netip.Addr]bool)
		var answer []assignedAddress
		for _, request := range requests {
			if request.id == 0 {
				return errors.New("masque: address request ID is zero")
			}
			a := netip.IPv4Unspecified()
			if request.prefix.Addr().Is6() {
				a = netip.IPv6Unspecified()
			}
			if t.server {
				for _, available := range t.addresses {
					candidate := available.prefix.Addr()
					if candidate.Is4() == a.Is4() && !used[candidate] {
						a = candidate
						used[a] = true
						break
					}
				}
			}
			answer = append(answer, assignedAddress{request.id, netip.PrefixFrom(a, a.BitLen())})
		}
		if t.server {
			for _, a := range t.addresses {
				if !used[a.prefix.Addr()] {
					answer = append(answer, a)
				}
			}
		}
		return t.write(capsuleAssign, encodeAddresses(answer))
	case capsuleRoutes:
		routes, err := parseRoutes(payload)
		if err != nil {
			return err
		}
		if t.onRoutes != nil {
			return t.onRoutes(routes)
		}
		t.stateMu.Lock()
		t.routes = routes
		t.routesAdvertised = true
		t.stateMu.Unlock()
	}
	return nil
}

func localAddresses(assigned []assignedAddress) []netip.Prefix {
	var addresses []netip.Prefix
	for _, a := range assigned {
		if a.prefix.Addr().IsUnspecified() && a.prefix.IsSingleIP() {
			continue
		}
		ip := a.prefix.Addr()
		if !a.prefix.IsSingleIP() {
			ip = ip.Next()
		}
		p := netip.PrefixFrom(ip, a.prefix.Bits())
		if !slices.Contains(addresses, p) {
			addresses = append(addresses, p)
		}
	}
	return addresses
}

func packetAddresses(p []byte) (netip.Addr, netip.Addr, bool) {
	if len(p) >= 20 && p[0]>>4 == 4 {
		header := int(p[0]&15) * 4
		if header < 20 || header > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), true
	}
	if len(p) >= 40 && p[0]>>4 == 6 && int(binary.BigEndian.Uint16(p[4:6]))+40 == len(p) {
		return netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40])), true
	}
	return netip.Addr{}, netip.Addr{}, false
}

func (t *tunnel) readPackets(ctx context.Context, device packetIO) error {
	for {
		kind, payload, err := readCapsule(t.reader)
		if err != nil {
			return err
		}
		if kind != capsuleDatagram {
			if err = t.control(kind, payload); err != nil {
				return err
			}
			continue
		}
		if err := t.deliver(ctx, device, payload); err != nil {
			return err
		}
	}
}

func (t *tunnel) deliver(ctx context.Context, device packetIO, payload []byte) error {
	r := bytes.NewReader(payload)
	id, err := readVarint(r)
	if err != nil {
		return err
	}
	if id != 0 || r.Len() == 0 || r.Len() > 65535 {
		return nil
	}
	p := payload[len(payload)-r.Len():]
	source, destination, valid := packetAddresses(p)
	if !valid {
		return nil
	}
	if t.onPacket != nil {
		return t.onPacket(ctx, p)
	}
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	address := destination
	if t.server {
		address = source
	}
	if !slices.ContainsFunc(t.addresses, func(a assignedAddress) bool { return a.prefix.Contains(address) }) {
		return nil
	}
	return device.WritePacket(ctx, p)
}

func (t *tunnel) run(ctx context.Context, device packetIO) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = t.conn.Close() })
	defer stop()
	results := make(chan error, 3)
	loops := 2
	go func() { results <- t.readPackets(ctx, device) }()
	datagrams, hasDatagrams := t.conn.(datagramTransport)
	if hasDatagrams {
		loops++
		go func() {
			for {
				p, err := datagrams.ReceiveDatagram(ctx)
				if err != nil {
					results <- err
					return
				}
				// Malformed or unknown-context unreliable datagrams are discarded.
				if len(p) == 0 {
					continue
				}
				if err := t.deliver(ctx, device, p); err != nil && ctx.Err() != nil {
					results <- err
					return
				}
			}
		}()
	}
	go func() {
		for {
			p, err := device.ReadPacket(ctx)
			if err != nil {
				results <- err
				return
			}
			if t.filterOutbound != nil {
				allowed, err := t.filterOutbound(ctx, p)
				if err != nil {
					results <- err
					return
				}
				if !allowed {
					continue
				}
			}
			payload := append([]byte{0}, p...)
			if hasDatagrams {
				err = datagrams.SendDatagram(payload)
				if err == nil {
					continue
				}
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) && t.onTooBig != nil {
					mtu := int(tooLarge.MaxDatagramPayloadSize) - 1
					if mtu < 1280 {
						results <- errors.New("masque: QUIC path cannot carry the minimum 1280-byte IP packet")
						return
					}
					if err := t.onTooBig(ctx, p, mtu); err != nil {
						results <- err
						return
					}
					continue
				}
				if !errors.Is(err, ErrDatagramsUnavailable) && !errors.Is(err, ErrDatagramTooLarge) && !errors.As(err, &tooLarge) {
					results <- err
					return
				}
			}
			if err := t.write(capsuleDatagram, payload); err != nil {
				results <- err
				return
			}
		}
	}()
	err := <-results
	cancel()
	_ = t.conn.Close()
	for i := 1; i < loops; i++ {
		<-results
	}
	return err
}

// packetIO decouples peer queues from the server's shared userspace device.
type packetIO interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
}
