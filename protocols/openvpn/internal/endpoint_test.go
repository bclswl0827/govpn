package openvpn

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEndpointReportsRekeyRequest(t *testing.T) {
	for _, test := range []struct {
		name   string
		opcode byte
	}{
		{"hard reset", ControlHardResetServerV2},
		{"soft reset", ControlSoftResetV1},
	} {
		t.Run(test.name, func(t *testing.T) { testEndpointRekey(t, test.opcode) })
	}
}

func TestEndpointProcessesControlWhenDataQueueIsFull(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	remote := SessionID{2}
	e := newEndpoint(client, SessionID{1}, remote)
	defer e.Close()
	// Drain ACKs so the server's simulated receive path cannot block the
	// endpoint. Leave the endpoint's IP data queue deliberately unread.
	go func() { _, _ = io.Copy(io.Discard, server) }()
	for range cap(e.dataCh) + 1 {
		if _, err := server.Write([]byte{DataV1 << 3, 1}); err != nil {
			t.Fatalf("data queue blocked the shared reader: %v", err)
		}
	}
	// An out-of-order payload must become readable after an empty control
	// packet fills the sequence gap, even while the IP queue stays full.
	for _, p := range []Packet{
		{Opcode: Control, LocalSessionID: remote, PacketID: 2, Payload: []byte("control")},
		{Opcode: Control, LocalSessionID: remote, PacketID: 1},
	} {
		wire, err := EncodeControl(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case payload := <-e.controlCh:
		if string(payload) != "control" {
			t.Fatalf("control payload = %q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("control reader stalled behind data or an empty control packet")
	}
}

func TestEndpointBoundsControlReordering(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// Exercise the reorder buffer without a concurrent socket reader.
	e := &endpoint{
		conn: client, expectedID: 1, reordered: make(map[uint32][]byte),
		controlCh: make(chan []byte, 64), errCh: make(chan error, 1), closed: make(chan struct{}),
	}
	for id := uint32(2); id <= uint32(cap(e.controlCh))+2; id++ {
		e.queueOrdered(id, []byte("waiting for missing packet"))
	}
	select {
	case err := <-e.Errors():
		if !strings.Contains(err.Error(), "reorder buffer exhausted") {
			t.Fatalf("error = %v", err)
		}
	default:
		t.Fatal("unbounded control reorder buffer")
	}
	if len(e.reordered) > cap(e.controlCh) {
		t.Fatalf("reorder buffer grew to %d entries", len(e.reordered))
	}
}

func testEndpointRekey(t *testing.T, opcode byte) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	local := SessionID{1}
	remote := SessionID{2}
	endpoint := newEndpoint(clientConn, local, remote)
	defer endpoint.Close()

	reset, err := EncodeControl(Packet{
		Opcode: opcode, KeyID: 1, LocalSessionID: remote, PacketID: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		if _, err := serverConn.Write(reset); err != nil {
			serverDone <- err
			return
		}
		buffer := make([]byte, 128)
		_, err := serverConn.Read(buffer)
		serverDone <- err
	}()

	select {
	case err := <-endpoint.Errors():
		if err == nil || !strings.Contains(err.Error(), "rekey requested") {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint did not report rekey request")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
