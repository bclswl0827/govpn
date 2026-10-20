package openvpn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ControlSoftResetV1       = 3
	ControlHardResetClientV2 = 7
	ControlHardResetServerV2 = 8
	Control                  = 4
	Ack                      = 5
	DataV1                   = 6
	DataV2                   = 9

	SessionIDSize     = 8
	MaxControlPayload = 1200
)

type SessionID [SessionIDSize]byte

func NewSessionID() (SessionID, error) {
	var id SessionID
	_, err := rand.Read(id[:])
	return id, err
}

type Packet struct {
	Opcode          byte
	KeyID           byte
	LocalSessionID  SessionID
	RemoteSessionID SessionID
	Acknowledgments []uint32
	PacketID        uint32
	Payload         []byte
	PeerID          uint32
}

func EncodeControl(packet Packet) ([]byte, error) {
	if packet.Opcode != ControlSoftResetV1 && packet.Opcode != ControlHardResetClientV2 && packet.Opcode != ControlHardResetServerV2 && packet.Opcode != Control && packet.Opcode != Ack {
		return nil, errors.New("openvpn: invalid control opcode")
	}
	if packet.KeyID > 7 || len(packet.Acknowledgments) > 255 {
		return nil, errors.New("openvpn: invalid control header")
	}
	length := 1 + SessionIDSize + 1 + 4*len(packet.Acknowledgments)
	if len(packet.Acknowledgments) != 0 {
		length += SessionIDSize
	}
	if packet.Opcode != Ack {
		length += 4 + len(packet.Payload)
	}
	result := make([]byte, length)
	result[0] = packet.Opcode<<3 | packet.KeyID
	copy(result[1:9], packet.LocalSessionID[:])
	offset := 9
	result[offset] = byte(len(packet.Acknowledgments))
	offset++
	for _, acknowledgment := range packet.Acknowledgments {
		binary.BigEndian.PutUint32(result[offset:offset+4], acknowledgment)
		offset += 4
	}
	if len(packet.Acknowledgments) != 0 {
		copy(result[offset:offset+8], packet.RemoteSessionID[:])
		offset += 8
	}
	if packet.Opcode != Ack {
		binary.BigEndian.PutUint32(result[offset:offset+4], packet.PacketID)
		offset += 4
		copy(result[offset:], packet.Payload)
	}
	return result, nil
}

func DecodeControl(data []byte) (Packet, error) {
	if len(data) < 10 {
		return Packet{}, errors.New("openvpn: truncated control packet")
	}
	packet := Packet{Opcode: data[0] >> 3, KeyID: data[0] & 7}
	if packet.Opcode != ControlSoftResetV1 && packet.Opcode != ControlHardResetClientV2 && packet.Opcode != ControlHardResetServerV2 && packet.Opcode != Control && packet.Opcode != Ack {
		return Packet{}, fmt.Errorf("openvpn: opcode %d is not a control packet", packet.Opcode)
	}
	copy(packet.LocalSessionID[:], data[1:9])
	count := int(data[9])
	offset := 10
	if len(data) < offset+4*count {
		return Packet{}, errors.New("openvpn: truncated acknowledgment array")
	}
	packet.Acknowledgments = make([]uint32, count)
	for i := range count {
		packet.Acknowledgments[i] = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if count != 0 {
		if len(data) < offset+8 {
			return Packet{}, errors.New("openvpn: truncated remote session ID")
		}
		copy(packet.RemoteSessionID[:], data[offset:offset+8])
		offset += 8
	}
	if packet.Opcode != Ack {
		if len(data) < offset+4 {
			return Packet{}, errors.New("openvpn: missing control packet ID")
		}
		packet.PacketID = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		packet.Payload = append([]byte(nil), data[offset:]...)
	} else if len(data) != offset {
		return Packet{}, errors.New("openvpn: trailing acknowledgment data")
	}
	return packet, nil
}

func Opcode(data []byte) (byte, error) {
	if len(data) == 0 {
		return 0, errors.New("openvpn: empty datagram")
	}
	return data[0] >> 3, nil
}

func DataHeader(opcode, keyID byte, peerID uint32) ([]byte, error) {
	if keyID > 7 || (opcode != DataV1 && opcode != DataV2) {
		return nil, errors.New("openvpn: invalid data header")
	}
	if peerID > 0xffffff {
		return nil, errors.New("openvpn: peer ID exceeds 24 bits")
	}
	header := []byte{opcode<<3 | keyID}
	if opcode == DataV2 {
		header = append(header, byte(peerID>>16), byte(peerID>>8), byte(peerID))
	}
	return header, nil
}
