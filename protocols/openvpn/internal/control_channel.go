package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type ControlProtection int

const (
	ControlProtectionNone ControlProtection = iota
	ControlProtectionAuth
	ControlProtectionCrypt
)

type ControlChannel struct {
	net.Conn
	mode       ControlProtection
	send       KeyPair
	receive    KeyPair
	digest     func() hash.Hash
	digestSize int
	sendID     uint32
	replay     replayWindow
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readBuffer []byte
}

func NewControlChannel(conn net.Conn, mode ControlProtection, keyValue []byte, auth string, direction int, directionSet, server bool) (*ControlChannel, error) {
	channel := &ControlChannel{Conn: conn, mode: mode, sendID: 1}
	if mode == ControlProtectionNone {
		return channel, nil
	}
	key, err := ParseStaticKey(keyValue)
	if err != nil {
		return nil, err
	}
	channel.send, channel.receive, err = key.directions(direction, directionSet, server, mode == ControlProtectionCrypt)
	if err != nil {
		return nil, err
	}
	if mode == ControlProtectionCrypt {
		channel.digest, channel.digestSize = sha256.New, sha256.Size
	} else {
		channel.digest, channel.digestSize, err = controlDigest(auth)
	}
	return channel, err
}

func controlDigest(name string) (func() hash.Hash, int, error) {
	switch strings.ToUpper(name) {
	case "", "SHA1", "SHA-1":
		return sha1.New, sha1.Size, nil
	case "MD5":
		return md5.New, md5.Size, nil
	case "SHA224", "SHA-224":
		return sha256.New224, sha256.Size224, nil
	case "SHA256", "SHA-256":
		return sha256.New, sha256.Size, nil
	case "SHA384", "SHA-384":
		return sha512.New384, sha512.Size384, nil
	case "SHA512", "SHA-512":
		return sha512.New, sha512.Size, nil
	default:
		return nil, 0, fmt.Errorf("openvpn: unsupported control authentication digest %q", name)
	}
}

func (c *ControlChannel) Write(plain []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wrapped, err := c.Wrap(plain)
	if err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(wrapped); err != nil {
		return 0, err
	}
	return len(plain), nil
}

func (c *ControlChannel) Read(buffer []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readBuffer == nil {
		c.readBuffer = make([]byte, 65535)
	}
	for {
		n, err := c.Conn.Read(c.readBuffer)
		if err != nil {
			return 0, err
		}
		plain, err := c.Unwrap(c.readBuffer[:n])
		if err != nil {
			// Authentication failures and replayed datagrams discard one
			// packet; they must not tear down an otherwise healthy tunnel.
			continue
		}
		if len(plain) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, plain), nil
	}
}

func (c *ControlChannel) Wrap(plain []byte) ([]byte, error) {
	if c.mode == ControlProtectionNone || isDataPacket(plain) {
		return append([]byte(nil), plain...), nil
	}
	if len(plain) < 9 || c.sendID == 0 {
		return nil, errors.New("openvpn: invalid control packet for wrapping")
	}
	packetID := make([]byte, 8)
	binary.BigEndian.PutUint32(packetID, c.sendID)
	binary.BigEndian.PutUint32(packetID[4:], uint32(time.Now().Unix()))
	c.sendID++
	header, body := plain[:9], plain[9:]
	if c.mode == ControlProtectionAuth {
		authenticated := make([]byte, 0, len(packetID)+len(plain))
		authenticated = append(authenticated, packetID...)
		authenticated = append(authenticated, plain...)
		mac := hmac.New(c.digest, c.send.HMAC[:c.digestSize])
		_, _ = mac.Write(authenticated)
		result := append([]byte(nil), header...)
		result = append(result, mac.Sum(nil)...)
		result = append(result, packetID...)
		return append(result, body...), nil
	}
	mac := hmac.New(sha256.New, c.send.HMAC[:sha256.Size])
	_, _ = mac.Write(header)
	_, _ = mac.Write(packetID)
	_, _ = mac.Write(body)
	tag := mac.Sum(nil)
	block, err := aes.NewCipher(c.send.Cipher[:32])
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(body))
	cipher.NewCTR(block, tag[:aes.BlockSize]).XORKeyStream(ciphertext, body)
	result := append([]byte(nil), header...)
	result = append(result, packetID...)
	result = append(result, tag...)
	return append(result, ciphertext...), nil
}

func (c *ControlChannel) Unwrap(wire []byte) ([]byte, error) {
	if c.mode == ControlProtectionNone || isDataPacket(wire) {
		return append([]byte(nil), wire...), nil
	}
	if len(wire) < 9+8+c.digestSize {
		return nil, errors.New("openvpn: protected control packet is truncated")
	}
	header := wire[:9]
	if c.mode == ControlProtectionAuth {
		tag := wire[9 : 9+c.digestSize]
		packetID := wire[9+c.digestSize : 9+c.digestSize+8]
		body := wire[9+c.digestSize+8:]
		plain := append(append([]byte(nil), header...), body...)
		authenticated := append(append([]byte(nil), packetID...), plain...)
		mac := hmac.New(c.digest, c.receive.HMAC[:c.digestSize])
		_, _ = mac.Write(authenticated)
		if subtle.ConstantTimeCompare(tag, mac.Sum(nil)) != 1 {
			return nil, errors.New("openvpn: tls-auth authentication failed")
		}
		if err := c.acceptPacketID(packetID); err != nil {
			return nil, err
		}
		return plain, nil
	}
	packetID := wire[9:17]
	tag := wire[17:49]
	ciphertext := wire[49:]
	block, err := aes.NewCipher(c.receive.Cipher[:32])
	if err != nil {
		return nil, err
	}
	body := make([]byte, len(ciphertext))
	cipher.NewCTR(block, tag[:aes.BlockSize]).XORKeyStream(body, ciphertext)
	mac := hmac.New(sha256.New, c.receive.HMAC[:sha256.Size])
	_, _ = mac.Write(header)
	_, _ = mac.Write(packetID)
	_, _ = mac.Write(body)
	if subtle.ConstantTimeCompare(tag, mac.Sum(nil)) != 1 {
		return nil, errors.New("openvpn: tls-crypt authentication failed")
	}
	if err := c.acceptPacketID(packetID); err != nil {
		return nil, err
	}
	return append(append([]byte(nil), header...), body...), nil
}

func isDataPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	opcode := packet[0] >> 3
	return opcode == DataV1 || opcode == DataV2
}

func (c *ControlChannel) acceptPacketID(value []byte) error {
	id := binary.BigEndian.Uint32(value)
	timestamp := int64(binary.BigEndian.Uint32(value[4:]))
	if id == 0 || timestamp < time.Now().Add(-time.Hour).Unix() || timestamp > time.Now().Add(time.Hour).Unix() || c.replay.seen(id) {
		return errors.New("openvpn: replayed control packet")
	}
	c.replay.mark(id)
	return nil
}

type replayWindow struct {
	last uint32
	bits uint64
}

func (r *replayWindow) seen(id uint32) bool {
	if id > r.last {
		return false
	}
	distance := r.last - id
	return distance >= 64 || r.bits&(uint64(1)<<distance) != 0
}

func (r *replayWindow) mark(id uint32) {
	if id > r.last {
		distance := id - r.last
		if distance >= 64 {
			r.bits = 0
		} else {
			r.bits <<= distance
		}
		r.last = id
		r.bits |= 1
		return
	}
	r.bits |= uint64(1) << (r.last - id)
}
