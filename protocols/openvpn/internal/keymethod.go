package openvpn

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const KeyMethod2 = 2

type KeyMethodMessage struct {
	Source   KeySource
	Options  string
	Username string
	Password string
	PeerInfo string
}

func WriteKeyMethod(w io.Writer, message KeyMethodMessage, server bool) error {
	var record bytes.Buffer
	header := []byte{0, 0, 0, 0, KeyMethod2}
	if _, err := record.Write(header); err != nil {
		return err
	}
	if !server {
		if _, err := record.Write(message.Source.PreMaster[:]); err != nil {
			return err
		}
	}
	if _, err := record.Write(message.Source.Random1[:]); err != nil {
		return err
	}
	if _, err := record.Write(message.Source.Random2[:]); err != nil {
		return err
	}
	for _, value := range []string{message.Options, message.Username, message.Password, message.PeerInfo} {
		if err := PutString(&record, value); err != nil {
			return err
		}
	}
	_, err := w.Write(record.Bytes())
	return err
}

func ReadKeyMethod(r io.Reader, server bool) (KeyMethodMessage, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return KeyMethodMessage{}, err
	}
	if binary.BigEndian.Uint32(header[:4]) != 0 || header[4]&7 != KeyMethod2 {
		return KeyMethodMessage{}, errors.New("openvpn: unsupported key-method record")
	}
	var message KeyMethodMessage
	if server {
		if _, err := io.ReadFull(r, message.Source.PreMaster[:]); err != nil {
			return KeyMethodMessage{}, err
		}
	}
	if _, err := io.ReadFull(r, message.Source.Random1[:]); err != nil {
		return KeyMethodMessage{}, err
	}
	if _, err := io.ReadFull(r, message.Source.Random2[:]); err != nil {
		return KeyMethodMessage{}, err
	}
	values := []*string{&message.Options, &message.Username, &message.Password, &message.PeerInfo}
	for _, target := range values {
		value, err := ReadString(r, 4096)
		if err != nil {
			return KeyMethodMessage{}, err
		}
		*target = value
	}
	return message, nil
}

func WriteCommand(w io.Writer, command string) error {
	_, err := io.WriteString(w, command+"\x00")
	return err
}

func ReadCommand(r *bufio.Reader, limit int) (string, error) {
	var command []byte
	for {
		chunk, err := r.ReadSlice(0)
		if len(command)+len(chunk) > limit {
			return "", errors.New("openvpn: control command exceeds limit")
		}
		command = append(command, chunk...)
		if err == nil {
			return string(command[:len(command)-1]), nil
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
}
