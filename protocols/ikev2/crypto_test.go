package ikev2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncryptedMessageRoundTrip(t *testing.T) {
	keys := ikeKeys{
		skAI: bytes.Repeat([]byte{1}, ikeIntegrityKeyLen),
		skAR: bytes.Repeat([]byte{2}, ikeIntegrityKeyLen),
		skEI: bytes.Repeat([]byte{3}, ikeEncryptionKeyLen),
		skER: bytes.Repeat([]byte{4}, ikeEncryptionKeyLen),
	}
	header := ikeHeader{
		initiatorSPI: 1, responderSPI: 2, exchange: exchangeInformation,
		flags: flagInitiator, messageID: 7,
	}
	message, err := encryptMessage(header, []payload{notifyPayload(16384, []byte("value"))}, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	decodedHeader, payloads, err := decryptMessage(message, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	if decodedHeader.messageID != 7 || len(payloads) != 1 || payloads[0].typeID != payloadNotify {
		t.Fatalf("unexpected decrypted message: header=%+v payloads=%+v", decodedHeader, payloads)
	}
	message[len(message)-1] ^= 1
	if _, _, err := decryptMessage(message, keys, true); err == nil {
		t.Fatal("tampered encrypted message passed integrity verification")
	}
}

func TestMODPPrimeSizes(t *testing.T) {
	if bits := modp1024Prime.BitLen(); bits != 1024 {
		t.Fatalf("MODP-1024 prime has %d bits", bits)
	}
	if bits := modp2048Prime.BitLen(); bits != 2048 {
		t.Fatalf("MODP-2048 prime has %d bits", bits)
	}
}

func TestESPTunnelRoundTrip(t *testing.T) {
	material := espKeyMaterial{
		i2rEncryption: bytes.Repeat([]byte{1}, espEncryptionKeyLen),
		i2rIntegrity:  bytes.Repeat([]byte{2}, espIntegrityKeyLen),
		r2iEncryption: bytes.Repeat([]byte{3}, espEncryptionKeyLen),
		r2iIntegrity:  bytes.Repeat([]byte{4}, espIntegrityKeyLen),
	}
	initiator := newInitiatorESP(20, 10, material)
	responder := newResponderESP(10, 20, material)
	inner := make([]byte, 24)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
	copy(inner[12:16], []byte{10, 60, 0, 2})
	copy(inner[16:20], []byte{10, 60, 0, 1})
	copy(inner[20:], []byte("ping"))

	packet, err := initiator.encapsulate(inner)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := responder.decapsulate(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, inner) {
		t.Fatalf("decapsulated packet = %x, want %x", opened, inner)
	}
	if _, err := responder.decapsulate(packet); err == nil {
		t.Fatal("replayed ESP packet was accepted")
	}
}
