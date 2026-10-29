package openvpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

func TestTransportSurvivesInvalidDataPackets(t *testing.T) {
	for _, compression := range []string{"", "lzo"} {
		t.Run(compression, func(t *testing.T) {
			device, err := packet.New("openvpn-receive-test", 1500)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = device.Close() })
			sender, err := protocol.NewDataCipher(protocol.KeyPair{})
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := protocol.NewDataCipher(protocol.KeyPair{})
			if err != nil {
				t.Fatal(err)
			}
			header, err := protocol.DataHeader(protocol.DataV1, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			seal := func(payload string) []byte {
				t.Helper()
				plain := []byte(payload)
				if compression == "lzo" {
					// LZO literal run followed by the end marker.
					plain = append([]byte{0x66, byte(17 + len(payload))}, plain...)
					plain = append(plain, 0x11, 0, 0)
				}
				wire, err := sender.Seal(header, plain)
				if err != nil {
					t.Fatal(err)
				}
				return wire
			}
			first, second := seal("first"), seal("second")
			corrupt := append([]byte(nil), second...)
			corrupt[len(corrupt)-1] ^= 1
			endpoint := &idleControlEndpoint{data: make(chan []byte, 4), errors: make(chan error, 1), closed: make(chan struct{})}
			for _, wire := range [][]byte{first, first, corrupt, second} {
				endpoint.data <- wire
			}
			transport := newTransport(endpoint, device, nil, receiver, false, 0, compression, 0, 0, nil)
			defer transport.Close()
			done := make(chan error, 1)
			go transport.run(done)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			for _, want := range []string{"first", "second"} {
				payload, err := device.Receive(ctx)
				if err != nil || string(payload) != want {
					t.Fatalf("Receive = %q, %v; want %q", payload, err, want)
				}
			}
			// Actual endpoint failures must still terminate the tunnel.
			failure := errors.New("underlying socket failed")
			endpoint.errors <- failure
			select {
			case err := <-done:
				if !errors.Is(err, failure) {
					t.Fatalf("terminal error = %v", err)
				}
			case <-ctx.Done():
				t.Fatal("transport ignored an endpoint failure")
			}
		})
	}
}
