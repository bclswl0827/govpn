package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
	transportutil "github.com/bclswl0827/govpn/internal/transport"
	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

type transport struct {
	endpoint interface {
		SendDatagram([]byte) error
		Data() <-chan []byte
		Errors() <-chan error
		Closed() <-chan struct{}
		Close() error
	}
	device        *packet.Device
	send          dataCipher
	receive       dataCipher
	usePeerID     bool
	peerID        uint32
	compression   string
	pingInterval  time.Duration
	pingTimeout   time.Duration
	logger        *log.Logger
	controlReader *bufio.Reader
	sendMu        sync.Mutex
	sendActivity  chan struct{}
	lastReceive   atomic.Int64
	pingSentLog   sync.Once
	pingRecvLog   sync.Once
	once          sync.Once
}

func newTransport(endpoint interface {
	SendDatagram([]byte) error
	Data() <-chan []byte
	Errors() <-chan error
	Closed() <-chan struct{}
	Close() error
}, device *packet.Device, send, receive dataCipher, usePeerID bool, peerID uint32, compression string, pingInterval, pingTimeout time.Duration, logger *log.Logger) *transport {
	return &transport{
		endpoint: endpoint, device: device, send: send, receive: receive,
		usePeerID: usePeerID, peerID: peerID, compression: compression,
		pingInterval: pingInterval, pingTimeout: pingTimeout,
		logger: logger, sendActivity: make(chan struct{}, 1),
	}
}

type dataCipher interface {
	Seal(header, plaintext []byte) ([]byte, error)
	Open(header, payload []byte) ([]byte, error)
}

func (t *transport) Close() error {
	var err error
	t.once.Do(func() { err = errors.Join(t.endpoint.Close(), t.device.Close()) })
	return err
}

func (t *transport) run(done chan<- error) {
	t.lastReceive.Store(time.Now().UnixNano())
	if t.pingInterval > 0 || t.pingTimeout > 0 {
		t.logf("keepalive configured: send-after=%s receive-timeout=%s", t.pingInterval, t.pingTimeout)
	}
	errCh := make(chan error, 4)
	if t.controlReader != nil {
		go func() { errCh <- t.readControlLoop() }()
	}
	go func() {
		for {
			payload, err := t.device.ReadPacket(context.Background())
			if err == nil {
				err = t.sendPacket(payload)
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	if t.pingInterval > 0 || t.pingTimeout > 0 {
		go t.keepaliveLoop(errCh)
	}
	go func() {
		var discarded uint64
		var nextDiscardLog time.Time
		decompressor := packetDecompressor{compression: t.compression}
		for {
			select {
			case datagram, ok := <-t.endpoint.Data():
				if !ok {
					errCh <- io.EOF
					return
				}
				if len(datagram) == 0 {
					continue
				}
				opcode := datagram[0] >> 3
				headerLength := 1
				if opcode == protocol.DataV2 {
					headerLength = 4
				}
				if len(datagram) < headerLength {
					continue
				}
				plaintext, err := t.receive.Open(datagram[:headerLength], datagram[headerLength:])
				if err == nil {
					plaintext, err = decompressor.decompress(plaintext)
				}
				if err != nil {
					discarded++
					if now := time.Now(); !now.Before(nextDiscardLog) {
						t.logf("discarded invalid data packets=%d latest-error=%v", discarded, err)
						nextDiscardLog = now.Add(30 * time.Second)
					}
					continue
				}
				t.lastReceive.Store(time.Now().UnixNano())
				if bytes.Equal(plaintext, openVPNPing) {
					t.pingRecvLog.Do(func() { t.logf("keepalive receive confirmed") })
					continue
				}
				if _, err := t.device.TryWritePacket(plaintext); err != nil {
					errCh <- err
					return
				}
			case err := <-t.endpoint.Errors():
				errCh <- err
				return
			case <-t.endpoint.Closed():
				// endpoint.fail publishes the specific transport error before it
				// closes the endpoint. Preserve that reason instead of racing the
				// closed notification and reporting a generic EOF.
				select {
				case err := <-t.endpoint.Errors():
					errCh <- err
				default:
					errCh <- io.EOF
				}
				return
			}
		}
	}()
	err := <-errCh
	err = transportutil.NormalizeError(err)
	if err != nil {
		t.logf("data channel stopped: %v", err)
	}
	_ = t.Close()
	done <- err
}

func (t *transport) readControlLoop() error {
	for {
		command, err := protocol.ReadCommand(t.controlReader, 16384)
		if err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				return io.EOF
			}
			return fmt.Errorf("openvpn: read control command: %w", err)
		}
		name, _, _ := strings.Cut(command, ",")
		switch name {
		case "INFO", "INFO_PRE", "ECHO", "AUTH_PENDING":
			continue
		case "RESTART", "HALT", "AUTH_FAILED":
			return fmt.Errorf("openvpn: server requested %s", name)
		case "PUSH_REPLY":
			return errors.New("openvpn: tunnel parameter update requires reconnect")
		default:
			return fmt.Errorf("openvpn: unsupported control command %q", name)
		}
	}
}

var openVPNPing = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

func (t *transport) sendPacket(payload []byte) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	payload, err := compressPacket(payload, t.compression)
	if err != nil {
		return err
	}
	opcode := byte(protocol.DataV1)
	if t.usePeerID {
		opcode = protocol.DataV2
	}
	header, err := protocol.DataHeader(opcode, 0, t.peerID)
	if err != nil {
		return err
	}
	datagram, err := t.send.Seal(header, payload)
	if err == nil {
		err = t.endpoint.SendDatagram(datagram)
	}
	if err == nil {
		select {
		case t.sendActivity <- struct{}{}:
		default:
		}
	}
	return err
}

func (t *transport) logf(format string, arguments ...any) {
	if t.logger != nil {
		t.logger.Printf("[openvpn] "+format, arguments...)
	}
}
