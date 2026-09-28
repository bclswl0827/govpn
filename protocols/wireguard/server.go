package wireguard

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/bclswl0827/govpn"
)

type Server struct {
	Config    ServerConfig
	runtimeMu sync.RWMutex
	runtime   *Runtime
}

func NewServer(config ServerConfig) *Server { return &Server{Config: config} }

func (s *Server) Start(ctx context.Context) (*govpn.Session, error) {
	if s.Config.ListenPort < 0 || s.Config.ListenPort > 65535 {
		return nil, fmt.Errorf("wireguard: listen port %d is out of range", s.Config.ListenPort)
	}
	if ip := s.Config.ListenIP; ip != "" && ip != "0.0.0.0" && ip != "::" {
		return nil, errors.New("wireguard: wireguard-go only supports wildcard ListenIP")
	}
	addressText := append([]string(nil), s.Config.Addresses...)
	if s.Config.Address != "" {
		addressText = append(addressText, s.Config.Address)
	}
	if s.Config.Address6 != "" {
		addressText = append(addressText, s.Config.Address6)
	}
	if len(addressText) == 0 {
		return nil, errors.New("wireguard: at least one address is required")
	}
	addresses, err := parseAddresses(addressText)
	if err != nil {
		return nil, err
	}
	peers, err := preparePeers(ctx, s.Config.Peers)
	if err != nil {
		return nil, err
	}
	mtu := normalizedMTU(s.Config.MTU)
	if mtu == 0 {
		return nil, fmt.Errorf("wireguard: invalid MTU %d", s.Config.MTU)
	}
	if err := validateAddressMTU(addresses, mtu); err != nil {
		return nil, err
	}
	uapi, err := buildUAPIWithMark(s.Config.PrivateKey, s.Config.ListenPort, s.Config.FirewallMark, peers)
	if err != nil {
		return nil, err
	}
	serverOptions := govpn.ServerSessionOptions{
		Protocol: govpn.ProtocolWireGuard, TrafficPolicy: s.Config.TrafficPolicy, OnTrafficDecision: s.Config.OnTrafficDecision,
	}
	session, runtime, err := start(addresses, mtu, uapi, peers, s.Config.Logger, &serverOptions)
	if err != nil {
		return nil, err
	}
	s.runtimeMu.Lock()
	s.runtime = runtime
	s.runtimeMu.Unlock()
	return session, nil
}

func (s *Server) Runtime() (*Runtime, error) {
	s.runtimeMu.RLock()
	defer s.runtimeMu.RUnlock()
	if s.runtime == nil {
		return nil, ErrNotStarted
	}
	return s.runtime, nil
}

func (s *Server) Status() (Status, error) {
	runtime, err := s.Runtime()
	if err != nil {
		return Status{}, err
	}
	return runtime.Status()
}

func (s *Server) UAPIGet() (string, error) {
	runtime, err := s.Runtime()
	if err != nil {
		return "", err
	}
	return runtime.UAPIGet()
}

func (s *Server) UAPISet(configuration string) error {
	runtime, err := s.Runtime()
	if err != nil {
		return err
	}
	return runtime.UAPISet(configuration)
}
