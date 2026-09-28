package openvpn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/netutil"
	"github.com/bclswl0827/govpn/internal/packet"
)

type Server struct{ Config ServerConfig }

func NewServer(config ServerConfig) *Server { return &Server{Config: config} }

func (s *Server) Start(ctx context.Context) (*govpn.Session, error) {
	if err := validateServer(s.Config); err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(s.Config.Cert, s.Config.Key)
	if err != nil {
		return nil, fmt.Errorf("openvpn: server certificate: %w", err)
	}
	tlsConfig, err := serverTLSConfig(s.Config, certificate)
	if err != nil {
		return nil, err
	}
	var network, network6 netip.Prefix
	var gateway, assigned, gateway6, assigned6 netip.Addr
	if s.Config.Pool != "" {
		network, gateway, assigned, err = netutil.ParseIPv4Pool(s.Config.Pool)
		if err != nil {
			return nil, fmt.Errorf("openvpn: %w", err)
		}
	}
	if s.Config.Pool6 != "" {
		network6, gateway6, assigned6, err = netutil.ParseIPv6Pool(s.Config.Pool6)
		if err != nil {
			return nil, fmt.Errorf("openvpn: %w", err)
		}
	}
	listenAddress := net.JoinHostPort(s.Config.ListenIP, strconv.Itoa(s.Config.ListenPort))
	mtu := effectiveMTU(s.Config.MTU)
	device, err := packet.New("openvpn-server", mtu)
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	var closeTransport func() error
	if strings.HasPrefix(serverTransportNetwork(s.Config), "tcp") {
		listener, listenErr := net.Listen(serverTransportNetwork(s.Config), listenAddress)
		if listenErr != nil {
			_ = device.Close()
			return nil, fmt.Errorf("openvpn: TCP listen: %w", listenErr)
		}
		transport := newServerStreamTransport(listener, device, s.Config)
		closeTransport = transport.Close
		go transport.accept(tlsConfig, network, gateway, assigned, network6, gateway6, assigned6, done)
	} else {
		packetConn, listenErr := net.ListenPacket(serverTransportNetwork(s.Config), listenAddress)
		if listenErr != nil {
			_ = device.Close()
			return nil, fmt.Errorf("openvpn: UDP listen: %w", listenErr)
		}
		transport := newServerTransport(packetConn, device, s.Config)
		closeTransport = transport.Close
		go transport.accept(tlsConfig, network, gateway, assigned, network6, gateway6, assigned6, done)
	}
	select {
	case <-ctx.Done():
		_ = closeTransport()
		return nil, ctx.Err()
	default:
	}
	addresses := make([]netip.Prefix, 0, 2)
	if network.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(gateway, network.Bits()))
	}
	if network6.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(gateway6, network6.Bits()))
	}
	return govpn.NewServerSession(addresses, uint32(mtu), device, closeTransport, done, govpn.ServerSessionOptions{
		Protocol: govpn.ProtocolOpenVPN, TrafficPolicy: s.Config.TrafficPolicy, OnTrafficDecision: s.Config.OnTrafficDecision,
	})
}

func serverTransportNetwork(config ServerConfig) string {
	if config.Protocol == "" {
		return "udp"
	}
	network := strings.ToLower(config.Protocol)
	switch network {
	case "tcp-server":
		return "tcp"
	case "tcp4-server":
		return "tcp4"
	case "tcp6-server":
		return "tcp6"
	default:
		return network
	}
}
