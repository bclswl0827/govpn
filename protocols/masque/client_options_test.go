package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestClientOptionsIsolation(t *testing.T) {
	tlsConfig := &tls.Config{ServerName: "tls.example", MinVersion: tls.VersionTLS13, NextProtos: []string{"original"}}
	c := Config{Server: "192.0.2.1", Port: 8443, Version: 3, TLSConfig: tlsConfig,
		ConnectURL: "https://authority.example/custom?q=1", Protocol: "vendor-ip",
		Headers: http.Header{"X-Test": {"original"}}, HTTP3: HTTP3Options{AdditionalSettings: map[uint64]uint64{0x276: 1}},
	}
	d, _, _, err := prepareClient(c)
	if err != nil {
		t.Fatal(err)
	}
	if d.Remote != "192.0.2.1:8443" || d.Request.Host != "authority.example" || d.TLSConfig.ServerName != "tls.example" || d.Request.Proto != "vendor-ip" || d.Request.URL.RequestURI() != "/custom?q=1" {
		t.Fatalf("dial address, authority, SNI or protocol lost: %+v", d)
	}
	d.TLSConfig.ServerName = "changed"
	d.Request.Header.Set("X-Test", "changed")
	d.HTTP3.AdditionalSettings[0x276] = 0
	if tlsConfig.ServerName != "tls.example" || c.Headers.Get("X-Test") != "original" || c.HTTP3.AdditionalSettings[0x276] != 1 {
		t.Fatal("caller configuration mutated")
	}
	defaults, _, addresses, err := prepareClient(Config{Server: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Version != 3 || defaults.Request.Proto != "connect-ip" || defaults.Request.URL.Path != DefaultPath || defaults.AllowMissingExtendedConnect || len(addresses) != 0 || defaults.TLSConfig.InsecureSkipVerify {
		t.Fatalf("standard defaults changed: %+v", defaults)
	}
}

func TestClientRejectsInvalidExtensionsBeforeDial(t *testing.T) {
	cases := map[string]func(*Config){
		"URL credentials":     func(c *Config) { c.ConnectURL = "https://user:password@example.com/" },
		"URL fragment":        func(c *Config) { c.ConnectURL = "https://example.com/#fragment" },
		"URL template":        func(c *Config) { c.ConnectURL = "https://example.com/{target}" },
		"insecure URL":        func(c *Config) { c.ConnectURL = "http://example.com/" },
		"pseudo header":       func(c *Config) { c.Headers = http.Header{":authority": {"evil"}} },
		"header injection":    func(c *Config) { c.Headers = http.Header{"X-Test": {"value\r\nInjected: yes"}} },
		"connection header":   func(c *Config) { c.Headers = http.Header{"connection": {"close"}} },
		"protocol injection":  func(c *Config) { c.Protocol = "bad protocol" },
		"reserved setting":    func(c *Config) { c.HTTP3.AdditionalSettings = map[uint64]uint64{0x33: 1} },
		"HTTP2 setting":       func(c *Config) { c.HTTP3.AdditionalSettings = map[uint64]uint64{2: 0} },
		"setting overflow":    func(c *Config) { c.HTTP3.AdditionalSettings = map[uint64]uint64{0x276: 1 << 62} },
		"connection ID":       func(c *Config) { c.HTTP3.ConnectionIDLength = 21 },
		"wrong version":       func(c *Config) { c.Version = 2; c.HTTP3.ConnectionIDLength = 20 },
		"unspecified address": func(c *Config) { c.Addresses = []netip.Addr{netip.IPv4Unspecified()} },
		"mapped address":      func(c *Config) { c.Addresses = []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.2")} },
		"multicast address":   func(c *Config) { c.Addresses = []netip.Addr{netip.MustParseAddr("ff02::1")} },
		"duplicate address": func(c *Config) {
			c.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.2")}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			c := Config{Server: "unused", Version: 3, Dialer: TunnelDialFunc(func(context.Context, DialRequest) (Tunnel, error) {
				called = true
				return nil, errors.New("unexpected dial")
			})}
			mutate(&c)
			if _, err := NewClient(c).Start(context.Background()); err == nil || called {
				t.Fatalf("err=%v dialed=%v", err, called)
			}
		})
	}
}

func TestCustomTunnelStaticAddressesAndLifetime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	var handshakeCtx context.Context
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}
	updates := make(chan Configuration, 8)
	session, err := NewClient(Config{Server: "unused", Addresses: addresses, ConfigurationChanged: func(c Configuration) { updates <- c },
		Dialer: TunnelDialFunc(func(ctx context.Context, d DialRequest) (Tunnel, error) { handshakeCtx = ctx; return local, nil }),
	}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if handshakeCtx.Err() == nil {
		t.Fatal("handshake context should be canceled after Start")
	}
	expected := []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32"), netip.MustParsePrefix("2001:db8::2/128")}
	if !reflect.DeepEqual(session.Addresses(), expected) {
		t.Fatalf("addresses=%v", session.Addresses())
	}
	// Start succeeds even though no peer reads ADDRESS_REQUEST or sends assignments.
	// The tunnel must remain alive after the handshake context was canceled.
	remote.SetWriteDeadline(time.Now().Add(time.Second))
	if err := writeCapsule(remote, 99, []byte("ignored extension")); err != nil {
		t.Fatalf("tunnel closed after Start: %v", err)
	}
	if err := writeCapsule(remote, capsuleAssign, encodeAddresses([]assignedAddress{{prefix: netip.MustParsePrefix("192.0.2.3/32")}})); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case update := <-updates:
			if len(update.Addresses) == 1 && update.Addresses[0].String() == "192.0.2.3/32" {
				if got := session.Addresses(); len(got) != 1 || got[0].String() != "192.0.2.3/32" {
					t.Fatalf("stack addresses=%v", got)
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("dynamic assignment not applied")
		}
	}
}

func TestCustomTunnelNegotiatesByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(3 * time.Second))
	peer := make(chan error, 1)
	go func() {
		kind, p, err := readCapsule(bufio.NewReader(remote))
		if err == nil && kind != capsuleRequest {
			err = errors.New("missing ADDRESS_REQUEST")
		}
		if err == nil {
			var a []assignedAddress
			a, err = parseAddresses(p)
			if err == nil && len(a) != 2 {
				err = errors.New("expected both address families")
			}
		}
		if err == nil {
			err = writeCapsule(remote, capsuleAssign, encodeAddresses([]assignedAddress{{prefix: netip.MustParsePrefix("192.0.2.2/32")}}))
		}
		peer <- err
	}()
	session, err := NewClient(Config{Server: "unused", Dialer: TunnelDialFunc(func(context.Context, DialRequest) (Tunnel, error) { return local, nil })}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	if got := session.Addresses(); len(got) != 1 || got[0].String() != "192.0.2.2/32" {
		t.Fatal(got)
	}
}

func TestCustomTunnelCanceledNegotiationClosesTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(3 * time.Second))
	finished := make(chan error, 1)
	go func() {
		_, err := NewClient(Config{Server: "unused", Dialer: TunnelDialFunc(func(context.Context, DialRequest) (Tunnel, error) { return local, nil })}).Start(ctx)
		finished <- err
	}()
	if _, _, err := readCapsule(bufio.NewReader(remote)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake did not stop")
	}
	if _, err := remote.Write([]byte{0}); err == nil {
		t.Fatal("canceled tunnel remained open")
	}
}

func TestCustomDialerFailure(t *testing.T) {
	sentinel := errors.New("private handshake failed")
	for _, test := range []struct {
		name string
		err  error
	}{
		{"error", sentinel}, {"nil tunnel", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewClient(Config{Server: "unused", Dialer: TunnelDialFunc(func(context.Context, DialRequest) (Tunnel, error) { return nil, test.err })}).Start(context.Background())
			if err == nil {
				t.Fatal("failed dial accepted")
			}
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("dial error lost: %v", err)
			}
		})
	}
}
