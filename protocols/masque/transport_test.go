package masque

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
	"github.com/quic-go/quic-go"
)

type testDatagramStream struct {
	net.Conn
	sendError error
	sent      chan []byte
}

func (s *testDatagramStream) SendDatagram(p []byte) error {
	if s.sendError != nil {
		return s.sendError
	}
	s.sent <- append([]byte(nil), p...)
	return nil
}
func (s *testDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDatagramCapsuleFallback(t *testing.T) {
	for _, test := range []struct {
		name      string
		sendError error
	}{
		{"custom-transport-too-large", ErrDatagramTooLarge}, {"datagram", nil}, {"capsules-only-peer", errDatagramsUnavailable}, {"datagram-too-large", &quic.DatagramTooLargeError{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			local, remote := net.Pipe()
			defer remote.Close()
			_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
			stream := &testDatagramStream{Conn: local, sendError: test.sendError, sent: make(chan []byte, 1)}
			device, err := packet.New("masque-fallback-test", 1280)
			if err != nil {
				t.Fatal(err)
			}
			defer device.Close()
			tunnel := &tunnel{conn: stream, reader: bufio.NewReader(stream)}
			stopped := make(chan error, 1)
			go func() { stopped <- tunnel.run(ctx, device) }()
			payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 2, 192, 0, 2, 1}
			if err := device.Inject(ctx, payload); err != nil {
				t.Fatal(err)
			}
			var got []byte
			if test.sendError == nil {
				select {
				case got = <-stream.sent:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			} else {
				kind, p, err := readCapsule(bufio.NewReader(remote))
				if err != nil || kind != capsuleDatagram {
					t.Fatalf("capsule: kind=%d err=%v", kind, err)
				}
				got = p
			}
			if !bytes.Equal(got, append([]byte{0}, payload...)) {
				t.Fatalf("payload: %x", got)
			}
			cancel()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("transport did not stop")
			}
		})
	}
}
