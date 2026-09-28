package ikev2

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestClientServerRoundTrip(t *testing.T) {
	ikePort := freeUDPPort(t)
	nattPort := freeUDPPort(t)
	for nattPort == ikePort {
		nattPort = freeUDPPort(t)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := NewServer(ServerConfig{
		ListenIP: "127.0.0.1", PublicIP: "127.0.0.1",
		IKEPort: ikePort, NATTPort: nattPort,
		Identity: "vpn.example", Users: map[string]string{"alice": "test-only-shared-secret"},
		Pool: "10.60.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	serverSession, err := server.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	listener, err := serverSession.Listen("tcp4", "10.60.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientSession, err := NewClient(Config{
		Server: "127.0.0.1", IKEPort: ikePort, NATTPort: nattPort,
		LocalID: "alice", RemoteID: "vpn.example", PSK: "test-only-shared-secret",
	}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			serverResult <- err
			return
		}
		if string(request) != "ping" {
			serverResult <- fmt.Errorf("unexpected request %q", request)
			return
		}
		_, err = connection.Write([]byte("pong"))
		serverResult <- err
	}()
	connection, err := clientSession.DialContext(ctx, "tcp4", "10.60.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply %q", reply)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
