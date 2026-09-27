package masque

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/bclswl0827/govpn"
)

func TestMultipleClientsAdvertisedSubnet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	certificates := httptest.NewTLSServer(http.NotFoundHandler())
	tlsConfig := certificates.TLS.Clone()
	certificates.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	listener.Close()
	endpoint := NewServer(ServerConfig{Versions: []int{2}, TLSConfig: tlsConfig, ListenIP: "127.0.0.1", ListenPort: port, Address: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}, Resolve: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{{}}, nil }})
	server, err := endpoint.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	config := Config{Server: "127.0.0.1", Port: port, Version: 2, SkipVerify: true, DisableVersionFallback: true, DisableReconnect: true}
	config.Target = "invalid.example"
	if rejected, err := NewClient(config).Start(ctx); err == nil {
		rejected.Close()
		t.Fatal("invalid DNS results granted unrestricted access")
	}
	config.Target = ""
	a, err := NewClient(config).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	config.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	b, err := NewClient(config).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.Addresses()[0] == b.Addresses()[0] {
		t.Fatal("duplicate client addresses")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(conn, conn)
		}
	}()
	forward, err := b.RegisterPortForward(ctx, govpn.PortForwardSpec{ListenAddress: "198.51.100.9:8080", TargetAddress: echo.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	// Wait until the server has consumed B's route announcement.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for endpoint.transport.lookup(netip.MustParseAddr("198.51.100.9"), 6) == nil {
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("route was not installed")
		}
	}
	conn, err := a.DialContext(ctx, "tcp", "198.51.100.9:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("routed")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 6)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "routed" {
		t.Fatal(string(reply))
	}
}
