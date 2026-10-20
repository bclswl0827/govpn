package openvpn

import (
	"bufio"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
)

type idleControlEndpoint struct {
	data   chan []byte
	errors chan error
	closed chan struct{}
	once   sync.Once
}

func (*idleControlEndpoint) SendDatagram([]byte) error { return nil }
func (e *idleControlEndpoint) Data() <-chan []byte     { return e.data }
func (e *idleControlEndpoint) Errors() <-chan error    { return e.errors }
func (e *idleControlEndpoint) Closed() <-chan struct{} { return e.closed }
func (e *idleControlEndpoint) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}

func TestOpenVPNControlLoopAfterHandshake(t *testing.T) {
	for _, command := range []string{"RESTART,reconnect", "HALT,shutdown", "AUTH_FAILED,expired"} {
		t.Run(command, func(t *testing.T) {
			device, err := packet.New("openvpn-control-test", 1500)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &idleControlEndpoint{data: make(chan []byte), errors: make(chan error), closed: make(chan struct{})}
			transport := newTransport(endpoint, device, nil, nil, false, 0, "", 0, 0, nil)
			defer transport.Close()
			// More than the endpoint's control queue capacity must be consumed
			// even when no data packets are flowing.
			messages := strings.Repeat("INFO,keep reading\x00", 128) + command + "\x00"
			transport.controlReader = bufio.NewReader(strings.NewReader(messages))
			done := make(chan error, 1)
			go transport.run(done)
			select {
			case err := <-done:
				name, _, _ := strings.Cut(command, ",")
				if err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("terminal error = %v, want %s", err, name)
				}
			case <-time.After(time.Second):
				t.Fatal("post-handshake control messages were not consumed")
			}
			select {
			case <-endpoint.closed:
			default:
				t.Fatal("terminal control command did not close the transport")
			}
		})
	}
}
