package govpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

// PortForwardSpec describes a TCP listener inside the userspace VPN stack and
// the host-network address to which accepted connections are forwarded.
// ListenAddress may be a concrete IP not assigned to the host; it becomes a
// virtual address inside the userspace stack only.
type PortForwardSpec struct {
	Network       string
	ListenAddress string
	TargetAddress string
}

// PortForward owns one registered TCP port. Close stops accepting connections
// and closes active proxied connections.
type PortForward struct {
	session  *Session
	listener net.Listener
	network  string
	target   string
	ctx      context.Context
	cancel   context.CancelFunc
	alias    netip.Addr
	aliasRef bool

	acceptDone  chan struct{}
	closeOnce   sync.Once
	connMu      sync.Mutex
	connections map[net.Conn]struct{}
}

// RegisterPortForward registers a TCP port in the userspace VPN stack.
// Accepted connections are dialed through the host network to TargetAddress.
func (s *Session) RegisterPortForward(ctx context.Context, spec PortForwardSpec) (*PortForward, error) {
	if s == nil {
		return nil, ErrSessionClosed
	}
	if ctx == nil {
		return nil, errors.New("govpn: nil port-forward context")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	network := strings.ToLower(strings.TrimSpace(spec.Network))
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("govpn: unsupported port-forward network %q", spec.Network)
	}
	if err := validateForwardAddress(spec.ListenAddress); err != nil {
		return nil, fmt.Errorf("govpn: port-forward listen address: %w", err)
	}
	if err := validateForwardTarget(spec.TargetAddress); err != nil {
		return nil, fmt.Errorf("govpn: port-forward target address: %w", err)
	}
	listenAddr, hasAlias, err := resolveForwardListenAddress(ctx, network, spec.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("govpn: port-forward listen address: %w", err)
	}
	aliasRef := false
	if hasAlias {
		var err error
		aliasRef, err = s.acquireForwardAlias(listenAddr)
		if err != nil {
			return nil, err
		}
	}
	listenAddress := spec.ListenAddress
	if hasAlias {
		_, port, _ := net.SplitHostPort(spec.ListenAddress)
		listenAddress = net.JoinHostPort(listenAddr.String(), port)
	}
	listener, err := s.Listen(network, listenAddress)
	if err != nil {
		if aliasRef {
			s.releaseForwardAlias(listenAddr)
		}
		return nil, fmt.Errorf("govpn: port-forward listen: %w", err)
	}
	forwardCtx, cancel := context.WithCancel(ctx)
	forward := &PortForward{
		session: s, listener: listener, network: network, target: spec.TargetAddress,
		ctx: forwardCtx, cancel: cancel, alias: listenAddr, aliasRef: aliasRef, acceptDone: make(chan struct{}),
		connections: make(map[net.Conn]struct{}),
	}
	if err := s.addForward(forward); err != nil {
		cancel()
		_ = listener.Close()
		if aliasRef {
			s.releaseForwardAlias(listenAddr)
		}
		return nil, err
	}
	go forward.acceptLoop()
	go func() {
		<-forwardCtx.Done()
		forward.shutdown()
	}()
	return forward, nil
}

func validateForwardAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port %q: %w", port, err)
	}
	if host == "" {
		return nil
	}
	return nil
}

func validateForwardTarget(address string) error {
	if err := validateForwardAddress(address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	if host == "" {
		return errors.New("target address must include a host")
	}
	return nil
}

func resolveForwardListenAddress(ctx context.Context, network, address string) (netip.Addr, bool, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return netip.Addr{}, false, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if strings.HasSuffix(network, "4") && !addr.Is4() || strings.HasSuffix(network, "6") && !addr.Is6() {
			return netip.Addr{}, false, fmt.Errorf("address %s does not match %s", addr, network)
		}
		return addr, true, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, false, err
	}
	for _, addr := range addresses {
		addr = addr.Unmap()
		if strings.HasSuffix(network, "4") && !addr.Is4() || strings.HasSuffix(network, "6") && !addr.Is6() {
			continue
		}
		return addr, true, nil
	}
	return netip.Addr{}, false, fmt.Errorf("no address for %q matching %s", host, network)
}

func (s *Session) acquireForwardAlias(address netip.Addr) (bool, error) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.closed {
		return false, ErrSessionClosed
	}
	if refs := s.forwardAliases[address]; refs > 0 {
		s.forwardAliases[address] = refs + 1
		return true, nil
	}
	for _, prefix := range s.stack.Addresses() {
		if prefix.Addr() == address {
			s.forwardAliases[address] = 1
			return true, nil
		}
	}
	if err := s.stack.AddAddress(netip.PrefixFrom(address, address.BitLen())); err != nil {
		return false, err
	}
	s.forwardAliases[address] = 1
	return true, nil
}

func (s *Session) releaseForwardAlias(address netip.Addr) {
	if !address.IsValid() {
		return
	}
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	refs := s.forwardAliases[address]
	if refs <= 1 {
		delete(s.forwardAliases, address)
		for _, prefix := range s.assignedAddresses {
			if prefix.Addr() == address {
				return
			}
		}
		_ = s.stack.RemoveAddress(netip.PrefixFrom(address, address.BitLen()))
		return
	}
	s.forwardAliases[address] = refs - 1
}

func (s *Session) addForward(forward *PortForward) error {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	s.forwards[forward] = struct{}{}
	return nil
}

func (s *Session) removeForward(forward *PortForward) {
	s.forwardMu.Lock()
	delete(s.forwards, forward)
	s.forwardMu.Unlock()
}

func (f *PortForward) acceptLoop() {
	defer close(f.acceptDone)
	defer f.shutdown()
	for {
		connection, err := f.listener.Accept()
		if err != nil {
			return
		}
		f.track(connection)
		go f.proxy(connection)
	}
}

func (f *PortForward) proxy(client net.Conn) {
	defer f.untrack(client)
	defer client.Close()
	target, err := (&net.Dialer{}).DialContext(f.ctx, f.network, f.target)
	if err != nil {
		return
	}
	f.track(target)
	defer f.untrack(target)
	defer target.Close()

	done := make(chan struct{}, 2)
	go copyAndSignal(target, client, done)
	go copyAndSignal(client, target, done)
	select {
	case <-done:
	case <-f.ctx.Done():
	}
}

func copyAndSignal(destination net.Conn, source net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(destination, source)
	done <- struct{}{}
}

func (f *PortForward) track(connection net.Conn) {
	f.connMu.Lock()
	f.connections[connection] = struct{}{}
	f.connMu.Unlock()
}

func (f *PortForward) untrack(connection net.Conn) {
	f.connMu.Lock()
	delete(f.connections, connection)
	f.connMu.Unlock()
}

func (f *PortForward) shutdown() {
	f.closeOnce.Do(func() {
		f.cancel()
		_ = f.listener.Close()
		f.connMu.Lock()
		for connection := range f.connections {
			_ = connection.Close()
		}
		f.connections = make(map[net.Conn]struct{})
		f.connMu.Unlock()
		f.session.removeForward(f)
		if f.aliasRef {
			f.session.releaseForwardAlias(f.alias)
		}
	})
}

// Close stops this port forward. It is safe to call more than once.
func (f *PortForward) Close() error {
	if f == nil {
		return nil
	}
	f.shutdown()
	<-f.acceptDone
	return nil
}
