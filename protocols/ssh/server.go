package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	gossh "golang.org/x/crypto/ssh"
)

type acceptedTunnel struct {
	channel   gossh.Channel
	device    *packet.Device
	addresses []netip.Prefix
	mtu       int
	request   TunnelRequest
	err       error
}

func (s *Server) Start(ctx context.Context) (*govpn.Session, error) {
	if s.Config.ListenPort <= 0 || s.Config.ListenPort > 65535 {
		return nil, fmt.Errorf("ssh: listen port %d is out of range", s.Config.ListenPort)
	}
	timeout, sshConfig, err := s.prepare()
	if err != nil {
		return nil, err
	}
	listenAddress := net.JoinHostPort(strings.TrimSpace(s.Config.ListenIP), strconv.Itoa(s.Config.ListenPort))
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("ssh: listen on %s: %w", listenAddress, err)
	}
	return s.serve(ctx, listener, timeout, sshConfig)
}

// Serve accepts one SSH connection from listener and takes ownership of the
// listener. It allows an application to supply its own listening lifecycle.
func (s *Server) Serve(ctx context.Context, listener net.Listener) (*govpn.Session, error) {
	if listener == nil {
		return nil, errors.New("ssh: listener is required")
	}
	timeout, sshConfig, err := s.prepare()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return s.serve(ctx, listener, timeout, sshConfig)
}

func (s *Server) prepare() (time.Duration, *gossh.ServerConfig, error) {
	timeout, sshConfig, err := prepareServer(s.Config)
	if err != nil {
		return 0, nil, err
	}
	if s.Config.ResolveTunnel == nil {
		if _, _, err := prepareTunnelSettings(TunnelSettings{Address: s.Config.Address, MTU: s.Config.MTU}); err != nil {
			return 0, nil, err
		}
	}
	if s.Config.KeepaliveInterval < 0 {
		return 0, nil, errors.New("ssh: keepalive interval cannot be negative")
	}
	return timeout, sshConfig, nil
}

func (s *Server) serve(ctx context.Context, listener net.Listener, timeout time.Duration, sshConfig *gossh.ServerConfig) (*govpn.Session, error) {
	stopAccept := context.AfterFunc(ctx, func() { _ = listener.Close() })
	rawConnection, err := listener.Accept()
	stopAccept()
	_ = listener.Close()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ssh: accept: %w", err)
	}
	closeRaw := true
	defer func() {
		if closeRaw {
			_ = rawConnection.Close()
		}
	}()

	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := rawConnection.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("ssh: set startup deadline: %w", err)
	}
	startupCtx, startupCancel := context.WithDeadline(ctx, deadline)
	defer startupCancel()
	stopContextClose := context.AfterFunc(ctx, func() { _ = rawConnection.Close() })
	defer stopContextClose()
	connection, channels, requests, err := gossh.NewServerConn(rawConnection, sshConfig)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ssh: handshake: %w", err)
	}
	closeConnection := true
	defer func() {
		if closeConnection {
			_ = connection.Close()
		}
	}()

	handlerCtx, handlerCancel := context.WithCancel(context.Background())
	tunnelResult := make(chan acceptedTunnel, 1)
	go s.serveGlobalRequests(handlerCtx, connection, requests)
	go s.serveChannels(startupCtx, handlerCtx, connection, channels, tunnelResult, true)

	var accepted acceptedTunnel
	select {
	case accepted = <-tunnelResult:
		if accepted.err != nil {
			handlerCancel()
			return nil, accepted.err
		}
	case <-startupCtx.Done():
		handlerCancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ssh: wait for TUN channel: %w", startupCtx.Err())
	}
	if err := rawConnection.SetDeadline(time.Time{}); err != nil {
		handlerCancel()
		_ = accepted.channel.Close()
		_ = accepted.device.Close()
		return nil, fmt.Errorf("ssh: clear startup deadline: %w", err)
	}

	transport := newTransportWithContext(
		connection,
		accepted.channel,
		accepted.device,
		accepted.mtu,
		s.Config.KeepaliveInterval,
		handlerCtx,
		handlerCancel,
		true,
	)
	done := make(chan error, 1)
	go transport.run(done)
	session, err := govpn.NewServerSession(
		accepted.addresses, uint32(accepted.mtu), accepted.device, transport.Close, done,
		govpn.ServerSessionOptions{Protocol: govpn.ProtocolSSH, TrafficPolicy: s.Config.TrafficPolicy, OnTrafficDecision: s.Config.OnTrafficDecision},
	)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	closeRaw = false
	closeConnection = false
	stopContextClose()
	s.logf("TUN channel established: user=%s unit=%s addresses=%v mtu=%d", connection.User(), requestUnitString(accepted.request.Unit), accepted.addresses, accepted.mtu)
	return session, nil
}

// HandleConn serves a general-purpose SSH connection and takes ownership of
// rawConnection. Shell, PTY, SFTP, forwarding, and other registered handlers
// work even when the peer never opens a TUN channel. onTunnel is called at
// most once when a userspace tunnel is established.
func (s *Server) HandleConn(ctx context.Context, rawConnection net.Conn, onTunnel TunnelSessionHandler) error {
	if rawConnection == nil {
		return errors.New("ssh: connection is required")
	}
	timeout, sshConfig, err := s.prepare()
	if err != nil {
		_ = rawConnection.Close()
		return err
	}
	defer rawConnection.Close()

	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := rawConnection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("ssh: set handshake deadline: %w", err)
	}
	stopContextClose := context.AfterFunc(ctx, func() { _ = rawConnection.Close() })
	defer stopContextClose()
	connection, channels, requests, err := gossh.NewServerConn(rawConnection, sshConfig)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("ssh: handshake: %w", err)
	}
	defer connection.Close()
	if err := rawConnection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("ssh: clear handshake deadline: %w", err)
	}

	handlerCtx, handlerCancel := context.WithCancel(context.Background())
	defer handlerCancel()
	tunnelResult := make(chan acceptedTunnel, 1)
	go s.serveGlobalRequests(handlerCtx, connection, requests)
	go s.serveChannels(handlerCtx, handlerCtx, connection, channels, tunnelResult, false)
	connectionDone := make(chan error, 1)
	go func() { connectionDone <- connection.Wait() }()

	var tunnelSession *govpn.Session
	defer func() {
		if tunnelSession != nil {
			_ = tunnelSession.Close()
		}
	}()
	for {
		select {
		case accepted := <-tunnelResult:
			if accepted.err != nil {
				return accepted.err
			}
			tunnelCtx, tunnelCancel := context.WithCancel(handlerCtx)
			transport := newTransportWithContext(
				connection,
				accepted.channel,
				accepted.device,
				accepted.mtu,
				s.Config.KeepaliveInterval,
				tunnelCtx,
				tunnelCancel,
				false,
			)
			done := make(chan error, 1)
			go transport.run(done)
			tunnelSession, err = govpn.NewServerSession(
				accepted.addresses, uint32(accepted.mtu), accepted.device, transport.Close, done,
				govpn.ServerSessionOptions{Protocol: govpn.ProtocolSSH, TrafficPolicy: s.Config.TrafficPolicy, OnTrafficDecision: s.Config.OnTrafficDecision},
			)
			if err != nil {
				_ = transport.Close()
				return err
			}
			s.logf("TUN channel established: user=%s unit=%s addresses=%v mtu=%d", connection.User(), requestUnitString(accepted.request.Unit), accepted.addresses, accepted.mtu)
			if onTunnel != nil {
				go onTunnel(tunnelCtx, connection, tunnelSession)
			}
			tunnelResult = nil
		case err := <-connectionDone:
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Server) serveChannels(startupCtx, handlerCtx context.Context, connection *gossh.ServerConn, channels <-chan gossh.NewChannel, tunnelResult chan<- acceptedTunnel, requireTunnel bool) {
	tunnelAccepted := false
	for newChannel := range channels {
		switch newChannel.ChannelType() {
		case "tun@openssh.com":
			if tunnelAccepted {
				_ = newChannel.Reject(gossh.ResourceShortage, "only one TUN channel is supported")
				continue
			}
			accepted := s.acceptTunnel(startupCtx, connection, newChannel)
			if accepted.err != nil {
				tunnelResult <- accepted
				return
			}
			tunnelAccepted = true
			tunnelResult <- accepted
		case "session":
			go s.serveSessionChannel(handlerCtx, connection, newChannel)
		default:
			handler := s.channelHandler(newChannel.ChannelType())
			if handler == nil {
				_ = newChannel.Reject(gossh.UnknownChannelType, "unsupported SSH channel type")
				continue
			}
			go handler(handlerCtx, connection, newChannel)
		}
	}
	if requireTunnel && !tunnelAccepted {
		tunnelResult <- acceptedTunnel{err: errors.New("ssh: connection closed before opening a TUN channel")}
	}
}

func (s *Server) acceptTunnel(ctx context.Context, connection *gossh.ServerConn, newChannel gossh.NewChannel) acceptedTunnel {
	request, err := parseTunnelRequest(newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(gossh.Prohibited, err.Error())
		return acceptedTunnel{err: err}
	}
	settings := TunnelSettings{Address: s.Config.Address, MTU: s.Config.MTU}
	if s.Config.ResolveTunnel != nil {
		settings, err = s.Config.ResolveTunnel(ctx, connection, request)
		if err != nil {
			err = fmt.Errorf("ssh: resolve TUN for user %q: %w", connection.User(), err)
			_ = newChannel.Reject(gossh.Prohibited, err.Error())
			return acceptedTunnel{err: err}
		}
	}
	addresses, mtu, err := prepareTunnelSettings(settings)
	if err != nil {
		_ = newChannel.Reject(gossh.Prohibited, err.Error())
		return acceptedTunnel{err: err}
	}
	device, err := packet.New("ssh-server", mtu)
	if err != nil {
		_ = newChannel.Reject(gossh.ResourceShortage, err.Error())
		return acceptedTunnel{err: err}
	}
	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		_ = device.Close()
		return acceptedTunnel{err: fmt.Errorf("ssh: accept TUN channel: %w", err)}
	}
	go gossh.DiscardRequests(channelRequests)
	return acceptedTunnel{channel: channel, device: device, addresses: addresses, mtu: mtu, request: request}
}

func parseTunnelRequest(payload []byte) (TunnelRequest, error) {
	if len(payload) != 8 {
		return TunnelRequest{}, errors.New("ssh: invalid TUN channel request")
	}
	var request TunnelRequest
	if err := gossh.Unmarshal(payload, &request); err != nil {
		return TunnelRequest{}, fmt.Errorf("ssh: decode TUN channel request: %w", err)
	}
	if request.Mode != TunnelModePointToPoint {
		return TunnelRequest{}, fmt.Errorf("ssh: unsupported TUN mode %d", request.Mode)
	}
	if request.Unit != TunnelUnitAny && request.Unit > sshTunnelIDMax {
		return TunnelRequest{}, fmt.Errorf("ssh: TUN unit %d is out of range", request.Unit)
	}
	return request, nil
}

func prepareTunnelSettings(settings TunnelSettings) ([]netip.Prefix, int, error) {
	addresses, err := parseAddresses(settings.Address)
	if err != nil {
		return nil, 0, err
	}
	mtu := settings.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 576 || mtu > maximumTunnelMTU {
		return nil, 0, fmt.Errorf("ssh: MTU must be between 576 and %d", maximumTunnelMTU)
	}
	for _, address := range addresses {
		if address.Addr().Is6() && mtu < 1280 {
			return nil, 0, fmt.Errorf("ssh: IPv6 requires an MTU of at least 1280, got %d", mtu)
		}
	}
	return addresses, mtu, nil
}

func requestUnitString(unit uint32) string {
	if unit == TunnelUnitAny {
		return "any"
	}
	return fmt.Sprint(unit)
}

var _ govpn.Server = (*Server)(nil)
