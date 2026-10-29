package sstp

import (
	"net"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func TestTransportRespondsToEchoWhenReceiveQueueIsFull(t *testing.T) {
	device, err := packet.New("sstp-congestion-test", 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	for {
		queued, err := device.TryWritePacket([]byte{0x45})
		if err != nil {
			t.Fatal(err)
		}
		if !queued {
			break
		}
	}
	_, _, dropsBefore := device.QueueStats()
	client, server := net.Pipe()
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	transport := newTransport(client, device, nil)
	defer transport.Close()
	done := make(chan error, 1)
	go transport.readPackets(protocol.NewFramer(client, client), done)
	peer := protocol.NewFramer(server, server)
	if err := peer.WriteData(protocol.EncodePPP(protocol.PPPIPv4, []byte{0x45})); err != nil {
		t.Fatal(err)
	}
	if err := peer.WriteControl(protocol.EchoRequest); err != nil {
		t.Fatalf("data queue blocked the keepalive reader: %v", err)
	}
	reply, err := peer.ReadPacket()
	if err != nil || !reply.Control || reply.Message != protocol.EchoResponse {
		t.Fatalf("keepalive reply = %+v, %v", reply, err)
	}
	_, _, dropsAfter := device.QueueStats()
	if dropsAfter != dropsBefore+1 {
		t.Fatalf("congestion drops = %d, want %d", dropsAfter, dropsBefore+1)
	}
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader did not stop after socket closure")
	}
}
