package softether

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/netutil"
	"github.com/bclswl0827/govpn/internal/packet"
)

type Server struct{ Config ServerConfig }

func NewServer(config ServerConfig) *Server { return &Server{Config: config} }

func (s *Server) Start(ctx context.Context) (*govpn.Session, error) {
	if s.Config.Hub == "" {
		return nil, errors.New("softether: hub is required")
	}
	if s.Config.ListenPort < 1 || s.Config.ListenPort > 65535 {
		return nil, errors.New("softether: listen port is out of range")
	}
	if s.Config.MaxConnections < 0 || s.Config.MaxConnections > 32 {
		return nil, errors.New("softether: MaxConnections is out of range")
	}
	if s.Config.MaxConnections > 1 {
		return nil, errors.New("softether: additional TCP connections are not implemented yet")
	}
	certificate, err := tls.X509KeyPair(s.Config.Cert, s.Config.Key)
	if err != nil {
		return nil, fmt.Errorf("softether: server certificate: %w", err)
	}
	network, gateway, assigned, err := netutil.ParseIPv4Pool(s.Config.Pool)
	if err != nil {
		return nil, fmt.Errorf("softether: %w", err)
	}
	dns, err := parseDNS(s.Config.DNS)
	if err != nil {
		return nil, err
	}
	mtu := s.Config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 576 || mtu > 65535 {
		return nil, errors.New("softether: MTU is out of range")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(s.Config.ListenIP, strconv.Itoa(s.Config.ListenPort)))
	if err != nil {
		return nil, fmt.Errorf("softether: listen: %w", err)
	}
	device, err := packet.New("softether-server", mtu)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	transport := newServerTransport(listener, device, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	done := make(chan error, 1)
	go transport.accept(s.Config, gateway, assigned, network.Bits(), dns, done)
	select {
	case <-ctx.Done():
		_ = transport.Close()
		return nil, ctx.Err()
	default:
	}
	return govpn.NewServerSession(
		[]netip.Prefix{netip.PrefixFrom(gateway, network.Bits())}, uint32(mtu), device, transport.Close, done,
		govpn.ServerSessionOptions{Protocol: govpn.ProtocolSoftEther, TrafficPolicy: s.Config.TrafficPolicy, OnTrafficDecision: s.Config.OnTrafficDecision},
	)
}
