package govpn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/protocols/masque"
	"github.com/bclswl0827/govpn/protocols/openvpn"
	"github.com/bclswl0827/govpn/protocols/softether"
	"github.com/bclswl0827/govpn/protocols/sstp"
	"github.com/bclswl0827/govpn/protocols/wireguard"
)

func TestProtocolRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		address string
		start   func(context.Context, *testing.T) (*govpn.Session, *govpn.Session)
	}{
		{name: "wireguard", address: "10.10.0.1:8080", start: startWireGuard},
		{name: "sstp", address: "10.20.0.1:8080", start: startSSTP},
		{name: "masque-http1", address: "10.50.0.1:8080", start: func(ctx context.Context, t *testing.T) (*govpn.Session, *govpn.Session) {
			return startMASQUE(ctx, t, 1)
		}},
		{name: "masque-http2", address: "10.50.0.1:8080", start: func(ctx context.Context, t *testing.T) (*govpn.Session, *govpn.Session) {
			return startMASQUE(ctx, t, 2)
		}},
		{name: "masque-http3", address: "10.50.0.1:8080", start: func(ctx context.Context, t *testing.T) (*govpn.Session, *govpn.Session) {
			return startMASQUE(ctx, t, 3)
		}},
		{name: "openvpn", address: "10.30.0.1:8080", start: startOpenVPN},
		{name: "softether", address: "10.40.0.1:8080", start: startSoftEther},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			server, client := test.start(ctx, t)
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			exerciseTCP(ctx, t, server, client, test.address)
			exerciseUDP(ctx, t, server, client, withPort(t, test.address, 8081))
		})
	}
}

func exerciseUDP(ctx context.Context, t *testing.T, server, client *govpn.Session, address string) {
	t.Helper()
	packetConn, err := server.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("listen UDP in VPN: %v", err)
	}
	defer packetConn.Close()
	_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))

	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		n, peer, err := packetConn.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if string(buf[:n]) != "ping" {
			serverErr <- fmt.Errorf("unexpected UDP request %q", buf[:n])
			return
		}
		_, err = packetConn.WriteTo([]byte("pong"), peer)
		serverErr <- err
	}()

	conn, err := client.DialContext(ctx, "udp4", address)
	if err != nil {
		t.Fatalf("dial UDP in VPN: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write UDP in VPN: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read UDP in VPN: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected UDP reply %q", reply)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("VPN UDP exchange: %v", err)
	}
}

func withPort(t *testing.T, address string, port int) string {
	t.Helper()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort(host, fmt.Sprint(port))
}

func startWireGuard(ctx context.Context, t *testing.T) (*govpn.Session, *govpn.Session) {
	t.Helper()
	port := freePort(t, "udp")
	serverPrivate, serverPublic, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, clientPublic, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	server, err := wireguard.NewServer(wireguard.ServerConfig{
		PrivateKey: serverPrivate,
		ListenIP:   "",
		ListenPort: port,
		Address:    "10.10.0.1/24",
		Peers: []wireguard.ServerPeer{{
			PublicKey:  clientPublic,
			AllowedIPs: []string{"10.10.0.2/32"},
		}},
	}).Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}

	client, err := wireguard.NewClient(wireguard.Config{
		PrivateKey: clientPrivate,
		Address:    []string{"10.10.0.2/24"},
		Peers: []wireguard.Peer{{
			PublicKey:  serverPublic,
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", port),
			AllowedIPs: []string{"10.10.0.0/24"},
		}},
	}).Start(ctx)
	if err != nil {
		_ = server.Close()
		t.Fatalf("start client: %v", err)
	}
	return server, client
}

func startSSTP(ctx context.Context, t *testing.T) (*govpn.Session, *govpn.Session) {
	t.Helper()
	port := freePort(t, "tcp")
	_, cert, key := testPKI(t)
	server, err := sstp.NewServer(sstp.ServerConfig{
		Cert:       cert,
		Key:        key,
		ListenIP:   "127.0.0.1",
		ListenPort: port,
		Pool:       "10.20.0.0/24",
		Users:      map[string]string{"alice": "correct horse battery staple"},
	}).Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	client, err := sstp.NewClient(sstp.Config{
		Server:     "127.0.0.1",
		Port:       port,
		Username:   "alice",
		Password:   "correct horse battery staple",
		SkipVerify: true,
	}).Start(ctx)
	if err != nil {
		_ = server.Close()
		t.Fatalf("start client: %v", err)
	}
	return server, client
}

func startOpenVPN(ctx context.Context, t *testing.T) (*govpn.Session, *govpn.Session) {
	t.Helper()
	port := freePort(t, "udp")
	ca, serverCert, serverKey := testPKI(t)
	clientCert, clientKey := signedLeaf(t, ca, false)
	server, err := openvpn.NewServer(openvpn.ServerConfig{
		CA:         ca.certPEM,
		Cert:       serverCert,
		Key:        serverKey,
		ListenIP:   "127.0.0.1",
		ListenPort: port,
		Pool:       "10.30.0.0/24",
	}).Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	client, err := openvpn.NewClient(openvpn.Config{
		Remote: "127.0.0.1",
		Port:   port,
		CA:     ca.certPEM,
		Cert:   clientCert,
		Key:    clientKey,
	}).Start(ctx)
	if err != nil {
		_ = server.Close()
		t.Fatalf("start client: %v", err)
	}
	return server, client
}

func startSoftEther(ctx context.Context, t *testing.T) (*govpn.Session, *govpn.Session) {
	t.Helper()
	port := freePort(t, "tcp")
	_, cert, key := testPKI(t)
	server, err := softether.NewServer(softether.ServerConfig{
		Cert: cert, Key: key, ListenIP: "127.0.0.1", ListenPort: port,
		Hub: "DEFAULT", Pool: "10.40.0.0/24", Users: map[string]string{"alice": "correct horse battery staple"},
	}).Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	client, err := softether.NewClient(softether.Config{
		Server: "127.0.0.1", Port: port, Hub: "DEFAULT", Username: "alice",
		Password: "correct horse battery staple", SkipVerify: true,
	}).Start(ctx)
	if err != nil {
		_ = server.Close()
		t.Fatalf("start client: %v", err)
	}
	return server, client
}

func exerciseTCP(ctx context.Context, t *testing.T, server, client *govpn.Session, address string) {
	t.Helper()
	listener, err := server.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("listen in VPN: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			serverErr <- err
			return
		}
		if string(request) != "ping" {
			serverErr <- fmt.Errorf("unexpected request %q", request)
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	conn, err := client.DialContext(ctx, "tcp4", address)
	if err != nil {
		t.Fatalf("dial in VPN: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write in VPN: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read in VPN: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply %q", reply)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("VPN server exchange: %v", err)
	}
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

type certificateAuthority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func testPKI(t *testing.T) (*certificateAuthority, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "govpn test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := &certificateAuthority{cert: template, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	cert, privateKey := signedLeaf(t, ca, true)
	return ca, cert, privateKey
}

func signedLeaf(t *testing.T, ca *certificateAuthority, server bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	name := "govpn test client"
	if server {
		usage = x509.ExtKeyUsageServerAuth
		name = "govpn test server"
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func startMASQUE(ctx context.Context, t *testing.T, version int) (*govpn.Session, *govpn.Session) {
	t.Helper()
	network := "tcp"
	if version == 3 {
		network = "udp"
	}
	port := freePort(t, network)
	ca, cert, key := testPKI(t)
	server, err := masque.NewServer(masque.ServerConfig{
		Versions: []int{version}, Cert: cert, Key: key, ListenIP: "127.0.0.1", ListenPort: port,
		Pool: "10.50.0.0/24", IPv6Pool: "fd00:50::/64",
		Users: map[string]string{"alice": "correct horse battery staple"},
	}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	// The shared test PKI has no DNS/IP SAN, so verification is explicitly
	// disabled here; the example uses a verified local CA and a SAN certificate.
	config := masque.Config{
		Server: "127.0.0.1", Port: port, Username: "alice", Password: "wrong",
		Version: version, CA: ca.certPEM, SkipVerify: true,
	}
	if unexpected, err := masque.NewClient(config).Start(ctx); err == nil {
		_ = unexpected.Close()
		t.Fatal("invalid credentials were accepted")
	}
	config.Password = "correct horse battery staple"
	client, err := masque.NewClient(config).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if addresses := client.Addresses(); len(addresses) != 2 || addresses[0].String() != "10.50.0.2/32" || addresses[1].String() != "fd00:50::2/128" {
		t.Fatalf("assigned addresses: %v", addresses)
	}
	second, err := masque.NewClient(config).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if second.Addresses()[0] == client.Addresses()[0] {
		t.Fatal("concurrent clients received the same address")
	}
	return server, client
}
