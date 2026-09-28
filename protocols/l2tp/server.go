package l2tp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/netutil"
	"github.com/bclswl0827/govpn/internal/packet"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/engine"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/logutil"
)

const defaultServerPool = "10.20.0.0/24"

type Server struct{ Config ServerConfig }

// NewServer validates a server configuration without opening listeners.
func NewServer(config ServerConfig) (*Server, error) {
	if _, err := resolveServerSettings(config); err != nil {
		return nil, err
	}
	return &Server{Config: config}, nil
}

func (s *Server) Start(ctx context.Context) (*govpn.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, err := resolveServerSettings(s.Config)
	if err != nil {
		return nil, err
	}
	ikeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: settings.listenIP, Port: settings.ikePort})
	if err != nil {
		return nil, fmt.Errorf("l2tp: bind IKE UDP/%d: %w", settings.ikePort, err)
	}
	nattConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: settings.listenIP, Port: settings.nattPort})
	if err != nil {
		_ = ikeConn.Close()
		return nil, fmt.Errorf("l2tp: bind NAT-T UDP/%d: %w", settings.nattPort, err)
	}
	device, err := packet.New("l2tp-server", settings.mtu)
	if err != nil {
		_ = ikeConn.Close()
		_ = nattConn.Close()
		return nil, err
	}
	runContext, cancelRun := context.WithCancel(ctx)
	transport := engine.NewServer(ikeConn, nattConn, packetIO{ctx: runContext, device: device}, engine.ServerConfig{
		PSK: []byte(s.Config.PSK), Users: s.Config.Users,
		PublicIP: settings.publicIP, Network: settings.network, Gateway: settings.gateway,
		DNS: settings.dns, IKEPort: settings.ikePort, NATTPort: settings.nattPort,
		Logger: logutil.New(settings.logger),
	})
	done := make(chan error, 1)
	go func() { done <- transport.Serve() }()
	closeTransport := func() error {
		cancelRun()
		return transport.Close()
	}
	address, _ := netip.AddrFromSlice(settings.gateway)
	session, err := govpn.NewServerSession(
		[]netip.Prefix{netip.PrefixFrom(address.Unmap(), settings.prefixBits)},
		uint32(settings.mtu), device, closeTransport, done,
		govpn.ServerSessionOptions{Protocol: govpn.ProtocolL2TP, TrafficPolicy: s.Config.TrafficPolicy, OnTrafficDecision: s.Config.OnTrafficDecision},
	)
	if err != nil {
		cancelRun()
		return nil, err
	}
	return session, nil
}

type serverSettings struct {
	listenIP, publicIP net.IP
	ikePort, nattPort  int
	network            *net.IPNet
	gateway            net.IP
	prefixBits, mtu    int
	dns                []net.IP
	logger             *log.Logger
}

func resolveServerSettings(config ServerConfig) (serverSettings, error) {
	if config.PSK == "" {
		return serverSettings{}, errors.New("l2tp: pre-shared key is required")
	}
	if len(config.Users) == 0 {
		return serverSettings{}, errors.New("l2tp: at least one user is required")
	}
	for username, password := range config.Users {
		if username == "" || password == "" {
			return serverSettings{}, errors.New("l2tp: usernames and passwords must not be empty")
		}
	}
	listenText := config.ListenIP
	if listenText == "" {
		listenText = "0.0.0.0"
	}
	listenIP := net.ParseIP(listenText).To4()
	if listenIP == nil {
		return serverSettings{}, fmt.Errorf("l2tp: invalid IPv4 listen address %q", listenText)
	}
	publicText := config.PublicIP
	if publicText == "" && !listenIP.IsUnspecified() {
		publicText = listenText
	}
	if publicText == "" {
		return serverSettings{}, errors.New("l2tp: PublicIP is required when ListenIP is unspecified")
	}
	publicIP := net.ParseIP(publicText).To4()
	if publicIP == nil {
		return serverSettings{}, fmt.Errorf("l2tp: invalid IPv4 public address %q", publicText)
	}
	if publicIP.IsUnspecified() {
		return serverSettings{}, errors.New("l2tp: PublicIP must be a concrete IPv4 address")
	}
	ikePort := config.IKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	nattPort := config.NATTPort
	if nattPort == 0 {
		nattPort = defaultNATTPort
	}
	if ikePort < 1 || ikePort > 65535 || nattPort < 1 || nattPort > 65535 {
		return serverSettings{}, errors.New("l2tp: IKE and NAT-T ports must be between 1 and 65535")
	}
	if ikePort == nattPort {
		return serverSettings{}, errors.New("l2tp: IKE and NAT-T ports must differ")
	}
	poolText := config.Pool
	if poolText == "" {
		poolText = defaultServerPool
	}
	networkPrefix, gatewayAddress, _, err := netutil.ParseIPv4Pool(poolText)
	if err != nil {
		return serverSettings{}, fmt.Errorf("l2tp: %w", err)
	}
	prefixBits := networkPrefix.Bits()
	network := &net.IPNet{
		IP:   append(net.IP(nil), networkPrefix.Addr().AsSlice()...),
		Mask: net.CIDRMask(prefixBits, 32),
	}
	gateway := append(net.IP(nil), gatewayAddress.AsSlice()...)
	mtu := config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 576 || mtu > defaultMTU {
		return serverSettings{}, fmt.Errorf("l2tp: MTU must be between 576 and %d", defaultMTU)
	}
	dns := make([]net.IP, 0, len(config.DNS))
	for _, address := range config.DNS {
		v4 := address.To4()
		if v4 == nil {
			return serverSettings{}, fmt.Errorf("l2tp: DNS address %q is not IPv4", address)
		}
		dns = append(dns, append(net.IP(nil), v4...))
	}
	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return serverSettings{
		listenIP: listenIP, publicIP: publicIP, ikePort: ikePort, nattPort: nattPort,
		network: network, gateway: gateway, prefixBits: prefixBits, mtu: mtu, dns: dns, logger: logger,
	}, nil
}

var _ govpn.Server = (*Server)(nil)
