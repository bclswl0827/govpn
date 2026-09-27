package masque

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
	"github.com/quic-go/quic-go"
)

func TestDatagramPathMTU(t *testing.T) {
	for _, capacity := range []int{1280, 1281, 1401} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			local, remote := net.Pipe()
			defer remote.Close()
			stream := &testDatagramStream{Conn: local, sendError: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(capacity)}}
			device, err := packet.New("mtu-test", 1500)
			if err != nil {
				t.Fatal(err)
			}
			defer device.Close()
			reported := make(chan int, 1)
			tunnel := &tunnel{conn: stream, reader: bufio.NewReader(stream), onTooBig: func(_ context.Context, _ []byte, mtu int) error { reported <- mtu; return nil }}
			done := make(chan error, 1)
			go func() { done <- tunnel.run(ctx, device) }()
			if err := device.Inject(ctx, testIPv4("192.0.2.2", "192.0.2.1", 64)); err != nil {
				t.Fatal(err)
			}
			if capacity < 1281 {
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), "minimum 1280") {
						t.Fatalf("error=%v", err)
					}
				case <-ctx.Done():
					t.Fatal("undersized path did not terminate")
				}
			} else {
				select {
				case mtu := <-reported:
					if mtu != capacity-1 {
						t.Fatalf("MTU=%d", mtu)
					}
				case <-ctx.Done():
					t.Fatal("missing PTB callback")
				}
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("transport did not stop")
				}
			}
		})
	}
}

func TestIPv6PacketTooBigAndHopLimit(t *testing.T) {
	p := make([]byte, 1400)
	p[0], p[6], p[7] = 0x60, 17, 1
	binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
	copy(p[8:24], netip.MustParseAddr("2001:db8::2").AsSlice())
	copy(p[24:40], netip.MustParseAddr("2001:db8::3").AsSlice())
	if decrementHopLimit(p) {
		t.Fatal("forwarded expired packet")
	}
	locals := []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64")}
	for _, kind := range []packetError{packetTooBig, hopLimitExceeded, noRoute} {
		reply := icmpError(p, kind, locals, 1280)
		if len(reply) != 1280 {
			t.Fatalf("reply length=%d", len(reply))
		}
		if kind == packetTooBig && (reply[40] != 2 || binary.BigEndian.Uint32(reply[44:48]) != 1280) {
			t.Fatal("invalid PTB")
		}
		if kind == hopLimitExceeded && reply[40] != 3 {
			t.Fatal("invalid time exceeded")
		}
		pseudo := append([]byte(nil), reply[8:40]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(reply)-40))
		pseudo = append(pseudo, 0, 0, 0, 58)
		pseudo = append(pseudo, reply[40:]...)
		if checksum(pseudo) != 0 {
			t.Fatal("invalid ICMPv6 checksum")
		}
		if icmpError(reply, noRoute, locals, 0) != nil {
			t.Fatal("replied to an ICMP error")
		}
	}
}

type oversizedH3Stream struct{ *testDatagramStream }

func (*oversizedH3Stream) CancelRead(quic.StreamErrorCode)  {}
func (*oversizedH3Stream) CancelWrite(quic.StreamErrorCode) {}

func TestHTTP3DatagramLimitExcludesFraming(t *testing.T) {
	underlying := &oversizedH3Stream{&testDatagramStream{sendError: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1400}}}
	stream := &h3Stream{quicStream: underlying, datagrams: true, datagramOverhead: 2}
	err := stream.SendDatagram(make([]byte, 1500))
	limit, ok := err.(*quic.DatagramTooLargeError)
	if !ok || limit.MaxDatagramPayloadSize != 1398 {
		t.Fatalf("adapter error=%v", err)
	}
}
