package masque

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

func prepareClient(c Config) (DialRequest, int, []assignedAddress, error) {
	var d DialRequest
	path := c.Path
	// A full CONNECT URL deliberately takes precedence over Path.
	if c.ConnectURL != "" {
		path = DefaultPath
	}
	template, err := parseTemplate(path)
	if err != nil {
		return d, 0, nil, err
	}
	path, mtu, err := options(template.expand(c.Target, c.IPProtocol), c.MTU)
	if err != nil {
		return d, 0, nil, err
	}
	port := c.Port
	if port == 0 {
		port = 443
	}
	if c.Server == "" || port < 1 || port > 65535 {
		return d, 0, nil, errors.New("masque: valid server and port are required")
	}
	d.Remote = net.JoinHostPort(c.Server, strconv.Itoa(port))
	d.Version = c.Version
	if d.Version == 0 {
		d.Version = 3
	}
	if d.Version < 1 || d.Version > 3 {
		return d, 0, nil, errors.New("masque: HTTP version must be 1, 2, or 3")
	}
	protocol := c.Protocol
	if protocol == "" {
		protocol = "connect-ip"
	}
	if !httpguts.ValidHeaderFieldName(protocol) {
		return d, 0, nil, errors.New("masque: invalid CONNECT protocol token")
	}
	if d.Version == 1 && (protocol != "connect-ip" || c.AllowMissingExtendedConnect) {
		return d, 0, nil, errors.New("masque: extended CONNECT options require HTTP/2 or HTTP/3")
	}
	u, _ := url.ParseRequestURI(path)
	u.Scheme, u.Host = "https", d.Remote
	if c.ConnectURL != "" {
		u, err = url.Parse(c.ConnectURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
			strings.ContainsAny(c.ConnectURL, "{}#\r\n") {
			return d, 0, nil, errors.New("masque: CONNECT URL must be an expanded HTTPS URL without userinfo or fragment")
		}
		if u.Path == "" {
			u.Path = "/"
		}
		if _, _, err = options(u.RequestURI(), mtu); err != nil {
			return d, 0, nil, err
		}
	}
	headers := make(http.Header)
	for name, values := range c.Headers {
		if !httpguts.ValidHeaderFieldName(name) {
			return d, 0, nil, errors.New("masque: invalid request header name")
		}
		switch strings.ToLower(name) {
		case "host", "connection", "upgrade", "transfer-encoding", "content-length", "keep-alive", "proxy-connection", "te", "trailer":
			return d, 0, nil, fmt.Errorf("masque: transport-owned header %q", name)
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return d, 0, nil, fmt.Errorf("masque: invalid value for header %q", name)
			}
			headers.Add(name, value)
		}
	}
	headers.Set("Capsule-Protocol", "?1")
	d.Request = &http.Request{Method: http.MethodConnect, Proto: protocol, URL: u, Host: u.Host, Header: headers}
	if c.Username != "" || c.Password != "" {
		d.Request.SetBasicAuth(c.Username, c.Password)
	}
	d.TLSConfig = &tls.Config{}
	if c.TLSConfig != nil {
		d.TLSConfig = c.TLSConfig.Clone()
	}
	if d.TLSConfig.MinVersion == 0 {
		d.TLSConfig.MinVersion = tls.VersionTLS12
	}
	if c.ServerName != "" {
		d.TLSConfig.ServerName = c.ServerName
	}
	if d.TLSConfig.ServerName == "" {
		d.TLSConfig.ServerName = c.Server
	}
	if c.SkipVerify {
		d.TLSConfig.InsecureSkipVerify = true
	}
	if len(c.CA) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(c.CA) {
			return d, 0, nil, errors.New("masque: invalid CA PEM")
		}
		d.TLSConfig.RootCAs = roots
	}
	d.AllowMissingExtendedConnect = c.AllowMissingExtendedConnect
	d.HTTP3.ConnectionIDLength = c.HTTP3.ConnectionIDLength
	if d.HTTP3.ConnectionIDLength < 0 || d.HTTP3.ConnectionIDLength > 20 {
		return d, 0, nil, errors.New("masque: HTTP/3 connection ID length must be 0..20")
	}
	if d.Version != 3 && (len(c.HTTP3.AdditionalSettings) != 0 || d.HTTP3.ConnectionIDLength != 0 || c.HTTP3.QUICConfig != nil) {
		return d, 0, nil, errors.New("masque: HTTP/3 options require version 3")
	}
	if d.Version == 3 {
		d.HTTP3.QUICConfig = quicConfigFor(c.HTTP3, mtu)
	}
	d.HTTP3.AdditionalSettings = make(map[uint64]uint64, len(c.HTTP3.AdditionalSettings))
	for id, value := range c.HTTP3.AdditionalSettings {
		// 0x2..0x5 are forbidden HTTP/2 settings; the others are owned by quic-go.
		if id >= 1<<62 || value >= 1<<62 || (id >= 1 && id <= 8) || id == 0x33 {
			return d, 0, nil, fmt.Errorf("masque: reserved or invalid HTTP/3 setting %#x", id)
		}
		d.HTTP3.AdditionalSettings[id] = value
	}
	if _, err := routesFromPrefixes(c.AdvertiseRoutes); err != nil {
		return d, 0, nil, err
	}
	if c.ReconnectInitial < 0 || c.ReconnectMax < 0 || c.ReconnectMax > 0 && c.ReconnectInitial > c.ReconnectMax {
		return d, 0, nil, errors.New("masque: invalid reconnect backoff")
	}
	var addresses []assignedAddress
	seen := make(map[netip.Addr]bool)
	for _, a := range c.Addresses {
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
			return d, 0, nil, errors.New("masque: static addresses must be unicast IPv4 or IPv6 host addresses")
		}
		if seen[a] {
			return d, 0, nil, errors.New("masque: duplicate static address")
		}
		seen[a] = true
		addresses = append(addresses, assignedAddress{prefix: netip.PrefixFrom(a, a.BitLen())})
	}
	return d, mtu, addresses, nil
}

// DefaultTunnelDialer establishes the built-in capsule transport. Wrappers may
// delegate to it with the prepared DialRequest received from Client.Start.
// Request and TLSConfig must be non-nil; their ownership follows DialRequest.
type DefaultTunnelDialer struct{}

func (DefaultTunnelDialer) DialTunnel(ctx context.Context, d DialRequest) (Tunnel, error) {
	if d.Request == nil || d.Request.URL == nil || d.TLSConfig == nil {
		return nil, errors.New("masque: incomplete dial request")
	}
	switch d.Version {
	case 1:
		return dialHTTP1(ctx, d.Remote, d.TLSConfig, d.Request)
	case 2:
		return dialHTTP2(ctx, d.Remote, d.TLSConfig, d.Request, d.AllowMissingExtendedConnect)
	case 3:
		return dialHTTP3Options(ctx, d.Remote, d.TLSConfig, d.Request, d.HTTP3, d.AllowMissingExtendedConnect)
	default:
		return nil, errors.New("masque: invalid dial HTTP version")
	}
}
