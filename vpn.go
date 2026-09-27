package govpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	userspacestack "github.com/bclswl0827/govpn/internal/netstack"
)

// Protocol identifies a supported VPN wire protocol.
type Protocol string

const (
	ProtocolWireGuard Protocol = "wireguard"
	ProtocolSSTP      Protocol = "sstp"
	ProtocolOpenVPN   Protocol = "openvpn"
	ProtocolSoftEther Protocol = "softether"
	ProtocolSSH       Protocol = "ssh"
	ProtocolL2TP      Protocol = "l2tp"
	ProtocolMASQUE    Protocol = "masque"
)

// Starter is the common lifecycle implemented by every protocol client and
// server. Start completes protocol setup and returns the same socket surface
// for both roles.
type Starter interface {
	Start(context.Context) (*Session, error)
}

// Client and Server deliberately have the same method set. The distinction is
// semantic: a client initiates a VPN transport and a server accepts one.
type Client interface{ Starter }
type Server interface{ Starter }

// PacketDevice is the raw-IP boundary between a VPN protocol and gVisor.
// Protocol packages normally supply this internally; it is exported to allow
// additional protocols to integrate without depending on implementation
// details of the gVisor adapter.
type PacketDevice interface {
	Inject(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

// Session exposes network operations backed by the in-process gVisor stack.
type Session struct {
	stack *userspacestack.Stack

	closeTransport    func() error
	terminalDone      chan struct{}
	terminalMu        sync.RWMutex
	terminalErr       error
	closeOnce         sync.Once
	closeErr          error
	forwardMu         sync.Mutex
	assignedAddresses []netip.Prefix // guarded by forwardMu; excludes forwarding aliases
	forwardAliases    map[netip.Addr]int
	forwards          map[*PortForward]struct{}
	closed            bool
}

type ICMPConn interface {
	net.PacketConn
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetTTL(int) error
	SetHopLimit(int) error
}

// ErrSessionClosed indicates that a session no longer accepts new sockets or
// port forwards.
var ErrSessionClosed = net.ErrClosed

// NewSession connects a running protocol packet device to a new gVisor stack.
// closeTransport tears down the protocol, while done reports its terminal
// error. Protocol implementations use this constructor after authentication.
func NewSession(addresses []netip.Prefix, mtu uint32, device PacketDevice, closeTransport func() error, done <-chan error) (*Session, error) {
	if closeTransport == nil {
		closeTransport = func() error { return nil }
	}
	s, err := userspacestack.New(addresses, mtu, device)
	if err != nil {
		_ = closeTransport()
		_ = device.Close()
		return nil, err
	}
	session := &Session{
		stack:             s,
		assignedAddresses: s.Addresses(),
		closeTransport:    closeTransport,
		terminalDone:      make(chan struct{}),
		forwardAliases:    make(map[netip.Addr]int),
		forwards:          make(map[*PortForward]struct{}),
	}
	if done != nil {
		go func() {
			err := <-done
			session.terminalMu.Lock()
			session.terminalErr = err
			session.terminalMu.Unlock()
			close(session.terminalDone)
			_ = session.Close()
		}()
	}
	return session, nil
}

// Addresses returns the IP prefixes assigned to the userspace stack.
func (s *Session) Addresses() []netip.Prefix { return s.stack.Addresses() }

// DialContext opens a TCP or UDP connection through the VPN.
func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.stack.DialContext(ctx, network, address)
}

// Dial implements net.Dialer-style dialing without a context.
func (s *Session) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

// Listen opens a TCP listener inside the VPN address space.
func (s *Session) Listen(network, address string) (net.Listener, error) {
	return s.stack.Listen(network, address)
}

// ListenPacket opens a UDP socket inside the VPN address space.
func (s *Session) ListenPacket(network, address string) (net.PacketConn, error) {
	return s.stack.ListenPacket(network, address)
}

func (s *Session) DialICMPContext(ctx context.Context, network, address string) (ICMPConn, error) {
	return s.stack.DialICMPContext(ctx, network, address)
}

func (s *Session) DialICMP(network, address string) (ICMPConn, error) {
	return s.DialICMPContext(context.Background(), network, address)
}

func (s *Session) DialICMP4Context(ctx context.Context, address string) (ICMPConn, error) {
	return s.DialICMPContext(ctx, "icmp4", address)
}

func (s *Session) DialICMP4(address string) (ICMPConn, error) {
	return s.DialICMP4Context(context.Background(), address)
}

func (s *Session) DialICMP6Context(ctx context.Context, address string) (ICMPConn, error) {
	return s.DialICMPContext(ctx, "icmp6", address)
}

func (s *Session) DialICMP6(address string) (ICMPConn, error) {
	return s.DialICMP6Context(context.Background(), address)
}

func (s *Session) ListenICMP(network, address string) (ICMPConn, error) {
	return s.stack.ListenICMP(network, address)
}

func (s *Session) ListenICMP4(address string) (ICMPConn, error) {
	return s.ListenICMP("icmp4", address)
}

func (s *Session) ListenICMP6(address string) (ICMPConn, error) {
	return s.ListenICMP("icmp6", address)
}

// Wait blocks until the protocol terminates, the session is closed, or ctx is
// canceled. A nil terminal error is returned for an orderly shutdown.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-s.terminalDone:
		return s.protocolError()
	default:
	}
	select {
	case <-s.terminalDone:
		return s.protocolError()
	case <-s.stack.Done():
		select {
		case <-s.terminalDone:
			return s.protocolError()
		default:
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) protocolError() error {
	s.terminalMu.RLock()
	defer s.terminalMu.RUnlock()
	return s.terminalErr
}

// Close tears down the protocol transport and gVisor stack. It is idempotent.
func (s *Session) Close() error {
	s.forwardMu.Lock()
	s.closed = true
	forwards := make([]*PortForward, 0, len(s.forwards))
	for forward := range s.forwards {
		forwards = append(forwards, forward)
	}
	s.forwardMu.Unlock()
	for _, forward := range forwards {
		_ = forward.Close()
	}
	s.closeOnce.Do(func() {
		transportErr := s.closeTransport()
		stackErr := s.stack.Close()
		s.closeErr = errors.Join(transportErr, stackErr)
	})
	return s.closeErr
}

// UpdateAddresses applies a protocol address assignment without replacing the
// Session. Sockets bound to removed addresses may fail; unchanged addresses and
// registered port-forward aliases are preserved. This changes no host networking.
func (s *Session) UpdateAddresses(addresses []netip.Prefix) error {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	combined := append([]netip.Prefix(nil), addresses...)
	for alias := range s.forwardAliases {
		found := false
		for _, p := range combined {
			if p.Addr() == alias {
				found = true
				break
			}
		}
		if !found {
			combined = append(combined, netip.PrefixFrom(alias, alias.BitLen()))
		}
	}
	if err := s.stack.ReplaceAddresses(combined); err != nil {
		return err
	}
	s.assignedAddresses = append([]netip.Prefix(nil), addresses...)
	return nil
}
