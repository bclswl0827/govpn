package openvpn

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestControlChannelTLSAuthRoundTripAndReplay(t *testing.T) {
	key := testStaticKey()
	client, err := NewControlChannel(nil, ControlProtectionAuth, key, "SHA256", 1, true, false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewControlChannel(nil, ControlProtectionAuth, key, "SHA256", 0, true, true)
	if err != nil {
		t.Fatal(err)
	}
	testControlProtectionRoundTrip(t, client, server)
}

func TestControlChannelTLSCryptRoundTripAndReplay(t *testing.T) {
	key := testStaticKey()
	client, err := NewControlChannel(nil, ControlProtectionCrypt, key, "", 0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewControlChannel(nil, ControlProtectionCrypt, key, "", 0, false, true)
	if err != nil {
		t.Fatal(err)
	}
	testControlProtectionRoundTrip(t, client, server)
}

func TestControlChannelDoesNotWrapDataPackets(t *testing.T) {
	channel, err := NewControlChannel(nil, ControlProtectionCrypt, testStaticKey(), "", 0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{DataV2 << 3, 0, 0, 1, 0xaa}
	wrapped, err := channel.Wrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	if string(wrapped) != string(packet) {
		t.Fatalf("data packet changed: %x", wrapped)
	}
}

func testControlProtectionRoundTrip(t *testing.T, client, server *ControlChannel) {
	t.Helper()
	plain, err := EncodeControl(Packet{Opcode: ControlHardResetClientV2, LocalSessionID: SessionID{1}, PacketID: 0})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := client.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := server.Unwrap(wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(plain) {
		t.Fatalf("decoded = %x, want %x", decoded, plain)
	}
	if _, err := server.Unwrap(wire); err == nil {
		t.Fatal("replayed protected control packet was accepted")
	}
}

func testStaticKey() []byte {
	value := make([]byte, 256)
	for i := range value {
		value[i] = byte(i)
	}
	return []byte("-----BEGIN OpenVPN Static key V1-----\n" + hex.EncodeToString(value) + "\n-----END OpenVPN Static key V1-----\n")
}

func TestControlChannelConnInterface(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	channel, err := NewControlChannel(left, ControlProtectionNone, nil, "", 0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(channel.LocalAddr().Network(), "pipe") {
		t.Fatalf("unexpected address: %v", channel.LocalAddr())
	}
}

func TestControlChannelReadSkipsInvalidAndReplayedPackets(t *testing.T) {
	for _, mode := range []ControlProtection{ControlProtectionAuth, ControlProtectionCrypt} {
		name := "tls-auth"
		if mode == ControlProtectionCrypt {
			name = "tls-crypt"
		}
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(2 * time.Second))
			receiver, err := NewControlChannel(left, mode, testStaticKey(), "SHA256", 1, true, false)
			if err != nil {
				t.Fatal(err)
			}
			sender, err := NewControlChannel(right, mode, testStaticKey(), "SHA256", 0, true, true)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := EncodeControl(Packet{Opcode: Control, LocalSessionID: SessionID{2}, PacketID: 1, Payload: []byte("first")})
			if err != nil {
				t.Fatal(err)
			}
			first, err := sender.Wrap(plain)
			if err != nil {
				t.Fatal(err)
			}
			second, err := sender.Wrap(plain)
			if err != nil {
				t.Fatal(err)
			}
			corrupt := append([]byte(nil), second...)
			corrupt[len(corrupt)-1] ^= 1
			data := []byte{DataV1 << 3, 1, 2, 3}
			written := make(chan error, 1)
			go func() {
				for _, wire := range [][]byte{first, first, corrupt, second} {
					if _, err := right.Write(wire); err != nil {
						written <- err
						return
					}
				}
				if _, err := sender.Write(data); err != nil {
					written <- err
					return
				}
				written <- right.Close()
			}()
			for _, want := range [][]byte{plain, plain, data} {
				buffer := make([]byte, 256)
				n, err := receiver.Read(buffer)
				if err != nil || string(buffer[:n]) != string(want) {
					t.Fatalf("Read = %x, %v; want %x", buffer[:n], err, want)
				}
			}
			if _, err := receiver.Read(make([]byte, 256)); !errors.Is(err, io.EOF) {
				t.Fatalf("underlying EOF = %v", err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		})
	}
}
