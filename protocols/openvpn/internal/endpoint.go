package openvpn

import (
	"errors"
	"net"
	"sync"
	"time"
)

type endpoint struct {
	conn       net.Conn
	local      SessionID
	remote     SessionID
	nextID     uint32
	writeMu    sync.Mutex
	pendingMu  sync.Mutex
	pending    map[uint32]*pendingControl
	expectedID uint32
	reordered  map[uint32][]byte
	controlCh  chan []byte
	dataCh     chan []byte
	errCh      chan error
	closed     chan struct{}
	closeOnce  sync.Once
}

type pendingControl struct {
	datagram []byte
	lastSent time.Time
	attempts int
}

func newEndpoint(conn net.Conn, local, remote SessionID) *endpoint {
	e := &endpoint{
		conn: conn, local: local, remote: remote, nextID: 1,
		controlCh: make(chan []byte, 64), dataCh: make(chan []byte, 256),
		errCh: make(chan error, 1), closed: make(chan struct{}),
		pending: make(map[uint32]*pendingControl), expectedID: 1,
		reordered: make(map[uint32][]byte),
	}
	go e.readLoop()
	go e.retransmitLoop()
	return e
}

func (e *endpoint) readLoop() {
	buffer := make([]byte, 65535)
	for {
		n, err := e.conn.Read(buffer)
		if err != nil {
			e.fail(err)
			return
		}
		datagram := append([]byte(nil), buffer[:n]...)
		opcode, err := Opcode(datagram)
		if err != nil {
			continue
		}
		switch opcode {
		case Control, ControlSoftResetV1, ControlHardResetClientV2, ControlHardResetServerV2, Ack:
			packet, err := DecodeControl(datagram)
			if err != nil || packet.LocalSessionID != e.remote {
				continue
			}
			if opcode != Ack {
				_ = e.sendAck(packet.PacketID)
			}
			if opcode == ControlSoftResetV1 || opcode == ControlHardResetClientV2 || opcode == ControlHardResetServerV2 {
				e.fail(errors.New("openvpn: data channel rekey requested; reconnect required"))
				return
			}
			for _, acknowledgment := range packet.Acknowledgments {
				e.pendingMu.Lock()
				delete(e.pending, acknowledgment)
				e.pendingMu.Unlock()
			}
			if opcode == Control {
				e.queueOrdered(packet.PacketID, packet.Payload)
			}
		case DataV1, DataV2:
			select {
			case e.dataCh <- datagram:
			case <-e.closed:
				return
			default:
				// IP data is lossy. Keep reading control packets and ACKs
				// even when the data consumer cannot keep up.
			}
		}
	}
}

func (e *endpoint) queueOrdered(packetID uint32, payload []byte) {
	if packetID < e.expectedID {
		return
	}
	if packetID > e.expectedID {
		if _, exists := e.reordered[packetID]; !exists {
			if len(e.reordered) >= cap(e.controlCh) {
				e.fail(errors.New("openvpn: control reorder buffer exhausted; reconnect required"))
				return
			}
			e.reordered[packetID] = append([]byte(nil), payload...)
		}
		return
	}
	for {
		if len(payload) != 0 {
			select {
			case e.controlCh <- payload:
			case <-e.closed:
				return
			}
		}
		e.expectedID++
		var exists bool
		payload, exists = e.reordered[e.expectedID]
		if !exists {
			return
		}
		delete(e.reordered, e.expectedID)
	}
}

func (e *endpoint) sendControl(payload []byte) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	packet := Packet{Opcode: Control, LocalSessionID: e.local, PacketID: e.nextID, Payload: payload}
	e.nextID++
	encoded, err := EncodeControl(packet)
	if err != nil {
		return err
	}
	e.pendingMu.Lock()
	e.pending[packet.PacketID] = &pendingControl{datagram: append([]byte(nil), encoded...), lastSent: time.Now(), attempts: 1}
	e.pendingMu.Unlock()
	_, err = e.conn.Write(encoded)
	if err != nil {
		e.pendingMu.Lock()
		delete(e.pending, packet.PacketID)
		e.pendingMu.Unlock()
	}
	return err
}

func (e *endpoint) sendAck(packetID uint32) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	encoded, err := EncodeControl(Packet{
		Opcode: Ack, LocalSessionID: e.local, RemoteSessionID: e.remote,
		Acknowledgments: []uint32{packetID},
	})
	if err != nil {
		return err
	}
	_, err = e.conn.Write(encoded)
	return err
}

func (e *endpoint) fail(err error) {
	select {
	case e.errCh <- err:
	default:
	}
	_ = e.Close()
}

func (e *endpoint) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.closed)
		err = e.conn.Close()
	})
	return err
}

func (e *endpoint) SendDatagram(datagram []byte) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	_, err := e.conn.Write(datagram)
	return err
}

func (e *endpoint) Data() <-chan []byte        { return e.dataCh }
func (e *endpoint) Errors() <-chan error       { return e.errCh }
func (e *endpoint) Closed() <-chan struct{}    { return e.closed }
func (e *endpoint) LocalSessionID() SessionID  { return e.local }
func (e *endpoint) RemoteSessionID() SessionID { return e.remote }
