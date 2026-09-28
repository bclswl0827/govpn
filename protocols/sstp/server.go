package sstp

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
	if s.Config.Shape != 0 {
		return nil, errors.New("sstp: Shape is not a protocol feature and is unsupported")
	}
	if s.Config.ListenPort <= 0 || s.Config.ListenPort > 65535 {
		return nil, fmt.Errorf("sstp: listen port %d is out of range", s.Config.ListenPort)
	}
	certificate, err := tls.X509KeyPair(s.Config.Cert, s.Config.Key)
	if err != nil {
		return nil, fmt.Errorf("sstp: server certificate: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("sstp: empty server certificate")
	}
	network, gateway, assigned, err := netutil.ParseIPv4Pool(s.Config.Pool)
	if err != nil {
		return nil, fmt.Errorf("sstp: %w", err)
	}
	address := net.JoinHostPort(s.Config.ListenIP, strconv.Itoa(s.Config.ListenPort))
	listener, err := tls.Listen("tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		return nil, fmt.Errorf("sstp: listen: %w", err)
	}
	device, err := packet.New("sstp-server", defaultMTU)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	transport := newServerTransport(listener, device)
	done := make(chan error, 1)
	go transport.accept(s.Config.Users, assigned, certificate.Certificate[0], done)
	select {
	case <-ctx.Done():
		_ = transport.Close()
		return nil, ctx.Err()
	default:
	}
	return govpn.NewServerSession(
		[]netip.Prefix{netip.PrefixFrom(gateway, network.Bits())}, defaultMTU, device, transport.Close, done,
		govpn.ServerSessionOptions{Protocol: govpn.ProtocolSSTP, TrafficPolicy: s.Config.TrafficPolicy, OnTrafficDecision: s.Config.OnTrafficDecision},
	)
}
