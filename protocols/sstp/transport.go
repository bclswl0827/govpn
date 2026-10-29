package sstp

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/bclswl0827/govpn/internal/packet"
	transportutil "github.com/bclswl0827/govpn/internal/transport"
	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

type transport struct {
	conn   net.Conn
	device *packet.Device
	logger *log.Logger
	txLogs atomic.Uint32
	rxLogs atomic.Uint32
	once   sync.Once
}

func newTransport(conn net.Conn, device *packet.Device, logger *log.Logger) *transport {
	return &transport{conn: conn, device: device, logger: logger}
}

func (t *transport) Close() error {
	var err error
	t.once.Do(func() { err = errors.Join(t.conn.Close(), t.device.Close()) })
	return err
}

func (t *transport) run(framer *protocol.Framer, done chan<- error) {
	errCh := make(chan error, 2)
	go t.writePackets(framer, errCh)
	go t.readPackets(framer, errCh)
	err := <-errCh
	err = transportutil.NormalizeError(err)
	if err != nil {
		t.logf("data channel stopped: %v", err)
	}
	_ = t.Close()
	done <- err
}

func (t *transport) writePackets(framer *protocol.Framer, errCh chan<- error) {
	for {
		packetBytes, err := t.device.ReadPacket(context.Background())
		if err == nil {
			err = framer.WriteData(protocol.EncodePPP(protocol.PPPIPv4, packetBytes))
			if err == nil {
				t.logPPP("TX", protocol.PPPIPv4, packetBytes)
			}
		}
		if err != nil {
			errCh <- err
			return
		}
	}
}

func (t *transport) readPackets(framer *protocol.Framer, errCh chan<- error) {
	for {
		packetValue, err := framer.ReadPacket()
		if err != nil {
			errCh <- err
			return
		}
		if packetValue.Control {
			if packetValue.Message == protocol.EchoRequest {
				err = framer.WriteControl(protocol.EchoResponse)
			} else if packetValue.Message == protocol.CallDisconnect {
				err = framer.WriteControl(protocol.CallDisconnectAck)
				if err == nil {
					err = io.EOF
				}
			}
			if err != nil {
				errCh <- err
				return
			}
			continue
		}
		frame, err := protocol.DecodePPP(packetValue.Payload)
		if err != nil {
			errCh <- err
			return
		}
		t.logPPP("RX", frame.Protocol, frame.Payload)
		if frame.Protocol == protocol.PPPIPv4 {
			if _, err := t.device.TryWritePacket(frame.Payload); err != nil {
				errCh <- err
				return
			}
		} else if frame.Protocol == protocol.PPPLCP {
			control, decodeErr := protocol.DecodeControl(frame.Payload)
			if decodeErr == nil && control.Code == protocol.EchoRequestCode {
				if err := writePPPControl(framer, protocol.PPPLCP, protocol.EchoReplyCode, control.ID, control.Payload); err != nil {
					errCh <- err
					return
				}
			}
		}
	}
}

func (t *transport) logPPP(direction string, pppProtocol uint16, payload []byte) {
	var count uint32
	if direction == "TX" {
		count = t.txLogs.Add(1)
	} else {
		count = t.rxLogs.Add(1)
	}
	if count > 8 || t.logger == nil {
		return
	}
	if pppProtocol == protocol.PPPLCP {
		control, err := protocol.DecodeControl(payload)
		if err == nil {
			name := "control"
			switch control.Code {
			case protocol.EchoRequestCode:
				name = "echo-request"
			case protocol.EchoReplyCode:
				name = "echo-reply"
			}
			t.logf("data %s: ppp=%#x code=%d(%s) id=%d length=%d", direction, pppProtocol, control.Code, name, control.ID, len(payload))
			return
		}
	}
	if pppProtocol == protocol.PPPIPv4 && len(payload) >= 20 && payload[0]>>4 == 4 {
		t.logf("data %s: ppp=%#x ip-protocol=%d source=%s destination=%s length=%d", direction, pppProtocol, payload[9], net.IP(payload[12:16]), net.IP(payload[16:20]), len(payload))
		return
	}
	t.logf("data %s: ppp=%#x length=%d", direction, pppProtocol, len(payload))
}

func (t *transport) logf(format string, arguments ...any) {
	if t.logger != nil {
		t.logger.Printf("[sstp] "+format, arguments...)
	}
}
