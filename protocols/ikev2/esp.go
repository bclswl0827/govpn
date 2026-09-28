package ikev2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
)

const (
	espHeaderLen = 8
	espICVLen    = 16
	ipv4Protocol = 4
)

type espDirection struct {
	spi        uint32
	encryption []byte
	integrity  []byte
}

type espSA struct {
	outbound espDirection
	inbound  espDirection

	outMu  sync.Mutex
	seq    uint32
	inMu   sync.Mutex
	window replayWindow
}

func newInitiatorESP(spiOut, spiIn uint32, material espKeyMaterial) *espSA {
	return &espSA{
		outbound: espDirection{spi: spiOut, encryption: material.i2rEncryption, integrity: material.i2rIntegrity},
		inbound:  espDirection{spi: spiIn, encryption: material.r2iEncryption, integrity: material.r2iIntegrity},
	}
}

func newResponderESP(spiOut, spiIn uint32, material espKeyMaterial) *espSA {
	return &espSA{
		outbound: espDirection{spi: spiOut, encryption: material.r2iEncryption, integrity: material.r2iIntegrity},
		inbound:  espDirection{spi: spiIn, encryption: material.i2rEncryption, integrity: material.i2rIntegrity},
	}
}

func (sa *espSA) encapsulate(inner []byte) ([]byte, error) {
	if _, err := validIPv4Packet(inner); err != nil {
		return nil, err
	}
	sa.outMu.Lock()
	if sa.seq == ^uint32(0) {
		sa.outMu.Unlock()
		return nil, errors.New("ikev2: ESP sequence space exhausted")
	}
	sa.seq++
	sequence := sa.seq
	sa.outMu.Unlock()

	paddingLength := (aes.BlockSize - (len(inner)+2)%aes.BlockSize) % aes.BlockSize
	plaintext := make([]byte, 0, len(inner)+paddingLength+2)
	plaintext = append(plaintext, inner...)
	for index := 0; index < paddingLength; index++ {
		plaintext = append(plaintext, byte(index+1))
	}
	plaintext = append(plaintext, byte(paddingLength), ipv4Protocol)

	block, err := aes.NewCipher(sa.outbound.encryption)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, espHeaderLen+aes.BlockSize+len(plaintext), espHeaderLen+aes.BlockSize+len(plaintext)+espICVLen)
	binary.BigEndian.PutUint32(packet[:4], sa.outbound.spi)
	binary.BigEndian.PutUint32(packet[4:8], sequence)
	iv := packet[espHeaderLen : espHeaderLen+aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(packet[espHeaderLen+aes.BlockSize:], plaintext)
	mac := hmac.New(sha256.New, sa.outbound.integrity)
	_, _ = mac.Write(packet)
	return append(packet, mac.Sum(nil)[:espICVLen]...), nil
}

func (sa *espSA) decapsulate(packet []byte) ([]byte, error) {
	if len(packet) < espHeaderLen+aes.BlockSize+aes.BlockSize+espICVLen {
		return nil, errors.New("ikev2: ESP packet is truncated")
	}
	if binary.BigEndian.Uint32(packet[:4]) != sa.inbound.spi {
		return nil, errors.New("ikev2: unexpected ESP SPI")
	}
	sequence := binary.BigEndian.Uint32(packet[4:8])
	if sequence == 0 {
		return nil, errors.New("ikev2: invalid ESP sequence")
	}
	messageEnd := len(packet) - espICVLen
	mac := hmac.New(sha256.New, sa.inbound.integrity)
	_, _ = mac.Write(packet[:messageEnd])
	if subtle.ConstantTimeCompare(mac.Sum(nil)[:espICVLen], packet[messageEnd:]) != 1 {
		return nil, errors.New("ikev2: ESP integrity check failed")
	}
	sa.inMu.Lock()
	if sa.window.seen(sequence) {
		sa.inMu.Unlock()
		return nil, errors.New("ikev2: replayed ESP packet")
	}
	sa.inMu.Unlock()

	iv := packet[espHeaderLen : espHeaderLen+aes.BlockSize]
	ciphertext := packet[espHeaderLen+aes.BlockSize : messageEnd]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ikev2: invalid ESP ciphertext length")
	}
	block, err := aes.NewCipher(sa.inbound.encryption)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	if len(plaintext) < 2 || plaintext[len(plaintext)-1] != ipv4Protocol {
		return nil, errors.New("ikev2: ESP payload is not an IPv4 tunnel packet")
	}
	paddingLength := int(plaintext[len(plaintext)-2])
	if paddingLength+2 > len(plaintext) {
		return nil, errors.New("ikev2: invalid ESP padding length")
	}
	paddingStart := len(plaintext) - paddingLength - 2
	for index := 0; index < paddingLength; index++ {
		if plaintext[paddingStart+index] != byte(index+1) {
			return nil, errors.New("ikev2: invalid ESP padding")
		}
	}
	inner := plaintext[:paddingStart]
	length, err := validIPv4Packet(inner)
	if err != nil {
		return nil, err
	}
	sa.inMu.Lock()
	if sa.window.seen(sequence) {
		sa.inMu.Unlock()
		return nil, errors.New("ikev2: replayed ESP packet")
	}
	sa.window.add(sequence)
	sa.inMu.Unlock()
	return append([]byte(nil), inner[:length]...), nil
}

func validIPv4Packet(packet []byte) (int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, errors.New("ikev2: invalid inner IPv4 packet")
	}
	headerLength := int(packet[0]&0x0f) * 4
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || length < headerLength || length > len(packet) {
		return 0, errors.New("ikev2: invalid inner IPv4 length")
	}
	return length, nil
}

type replayWindow struct {
	top  uint32
	mask uint64
}

func (window *replayWindow) seen(sequence uint32) bool {
	if sequence == 0 {
		return true
	}
	if sequence > window.top {
		return false
	}
	difference := window.top - sequence
	return difference >= 64 || window.mask&(uint64(1)<<difference) != 0
}

func (window *replayWindow) add(sequence uint32) {
	if sequence > window.top {
		shift := sequence - window.top
		if shift >= 64 {
			window.mask = 0
		} else {
			window.mask <<= shift
		}
		window.mask |= 1
		window.top = sequence
		return
	}
	difference := window.top - sequence
	if difference < 64 {
		window.mask |= uint64(1) << difference
	}
}
