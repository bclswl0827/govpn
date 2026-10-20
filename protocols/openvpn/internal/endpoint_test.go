package openvpn

import (
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
