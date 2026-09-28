package govpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ErrTrafficDenied indicates that TrafficPolicy rejected every resolved
// address for a server-mediated connection.
var ErrTrafficDenied = errors.New("govpn: traffic denied by policy")

// DialEgressContext opens a host-network connection on behalf of a VPN client.
// The target hostname is resolved first and each concrete IP is evaluated as
// server-egress traffic before it is dialed. source may be nil when the
// originating client address is unavailable.
func (s *Session) DialEgressContext(ctx context.Context, network, address string, source net.Addr) (net.Conn, error) {
	if s == nil {
		return nil, ErrSessionClosed
	}
	s.forwardMu.Lock()
	closed := s.closed
	s.forwardMu.Unlock()
	if closed {
		return nil, ErrSessionClosed
	}
	ipProtocol, err := egressIPProtocol(network)
	if err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("govpn: invalid egress port %q: %w", portText, err)
	}
	sourceIP, sourcePort := trafficAddress(source)
	addresses, err := resolveEgressAddresses(ctx, network, host)
	if err != nil {
		return nil, err
	}
	var lastDialError error
	allowed := false
	for _, destination := range addresses {
		decision := s.EvaluateTraffic(TrafficFlow{
			Direction:       TrafficDirectionServerEgress,
			SourceIP:        sourceIP,
			DestinationIP:   destination.WithZone(""),
			DestinationHost: host,
			IPProtocol:      ipProtocol,
			SourcePort:      sourcePort,
			DestinationPort: uint16(portValue),
			PortsValid:      true,
		})
		if !decision.Allowed() {
			continue
		}
		allowed = true
		connection, dialErr := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(destination.String(), portText))
		if dialErr == nil {
			return connection, nil
		}
		lastDialError = dialErr
	}
	if !allowed {
		return nil, fmt.Errorf("%w: %s", ErrTrafficDenied, address)
	}
	return nil, lastDialError
}

func egressIPProtocol(network string) (uint8, error) {
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
		return 6, nil
	case "udp", "udp4", "udp6":
		return 17, nil
	default:
		return 0, fmt.Errorf("govpn: unsupported egress network %q", network)
	}
}

func resolveEgressAddresses(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if matchesEgressNetwork(network, address) {
			return []netip.Addr{address}, nil
		}
		return nil, fmt.Errorf("govpn: address %s does not match %s", address, network)
	}
	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, address := range resolved {
		address = address.Unmap()
		if matchesEgressNetwork(network, address) {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("govpn: no address for %q matching %s", host, network)
	}
	return addresses, nil
}

func matchesEgressNetwork(network string, address netip.Addr) bool {
	switch strings.ToLower(network) {
	case "tcp4", "udp4":
		return address.Is4()
	case "tcp6", "udp6":
		return address.Is6()
	default:
		return true
	}
}

func trafficAddress(address net.Addr) (netip.Addr, uint16) {
	switch value := address.(type) {
	case *net.TCPAddr:
		return trafficIPPort(value.IP, value.Port)
	case *net.UDPAddr:
		return trafficIPPort(value.IP, value.Port)
	default:
		return netip.Addr{}, 0
	}
}

func trafficIPPort(ip net.IP, port int) (netip.Addr, uint16) {
	if port < 0 || port > 65535 {
		return netip.Addr{}, 0
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, uint16(port)
	}
	return address.Unmap().WithZone(""), uint16(port)
}
