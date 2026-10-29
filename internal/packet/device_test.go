package packet

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func TestDevicePacketBoundaryCopiesBuffers(t *testing.T) {
	d, err := New("test", 1400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	source := []byte{0x45, 1, 2, 3}
	if err := d.Inject(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	source[1] = 9

	buffer := make([]byte, 16)
	sizes := make([]int, 1)
	n, err := d.Read([][]byte{buffer}, sizes, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || sizes[0] != 4 || buffer[3] != 1 {
		t.Fatalf("Read = (%d, %d, %v), want copied four-byte packet", n, sizes[0], buffer[2:6])
	}

	buffer[2] = 0x60
	if _, err := d.Write([][]byte{buffer[2:6]}, 0); err != nil {
		t.Fatal(err)
	}
	buffer[3] = 8
	packet, err := d.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packet[0] != 0x60 || packet[1] != 1 {
		t.Fatalf("Receive = %v, want independent copy", packet)
	}
}

func TestDeviceLifecycleAndMetadata(t *testing.T) {
	d, err := New("test", 1280)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := d.Name(); name != "test" {
		t.Fatalf("Name = %q", name)
	}
	if mtu, _ := d.MTU(); mtu != 1280 {
		t.Fatalf("MTU = %d", mtu)
	}
	if event := <-d.Events(); event != tun.EventUp {
		t.Fatalf("event = %v, want EventUp", event)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := d.Inject(context.Background(), []byte{1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Inject after Close = %v", err)
	}
	if _, err := d.Receive(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Receive after Close = %v", err)
	}
}

func TestDeviceWriteBatch(t *testing.T) {
	d, err := New("test", 1400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	n, err := d.Write([][]byte{{9, 1}, {9, 2}, {9, 3}}, 1)
	if err != nil || n != 3 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	for want := byte(1); want <= 3; want++ {
		packet, err := d.Receive(context.Background())
		if err != nil || len(packet) != 1 || packet[0] != want {
			t.Fatalf("Receive = %v, %v; want %d", packet, err, want)
		}
	}
}

func TestNewRejectsInvalidMetadata(t *testing.T) {
	for _, test := range []struct {
		name string
		mtu  int
	}{
		{"", 1400},
		{"test", 0},
		{"test", 65536},
	} {
		if _, err := New(test.name, test.mtu); err == nil {
			t.Fatalf("New(%q, %d) succeeded", test.name, test.mtu)
		}
	}
}

func TestTryWritePacketDropsCongestionAndRecovers(t *testing.T) {
	d, err := New("test", 1400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	source := []byte{0x45, 1}
	for range cap(d.fromProtocol) {
		if queued, err := d.TryWritePacket(source); !queued || err != nil {
			t.Fatalf("TryWritePacket = %t, %v", queued, err)
		}
	}
	source[1] = 9

	type result struct {
		queued bool
		err    error
	}
	done := make(chan result, 1)
	go func() {
		queued, err := d.TryWritePacket(source)
		done <- result{queued, err}
	}()
	select {
	case result := <-done:
		if result.queued || result.err != nil {
			t.Fatalf("full queue = %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("full receive queue blocked the transport")
	}
	_, depth, drops := d.QueueStats()
	if depth != cap(d.fromProtocol) || drops != 1 {
		t.Fatalf("queue depth = %d, drops = %d", depth, drops)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload, err := d.Receive(ctx)
	if err != nil || len(payload) != 2 || payload[1] != 1 {
		t.Fatalf("Receive = %v, %v; want independent copy", payload, err)
	}
	if queued, err := d.TryWritePacket(source); !queued || err != nil {
		t.Fatalf("queue did not recover: %t, %v", queued, err)
	}
	_ = d.Close()
	if queued, err := d.TryWritePacket(source); queued || !errors.Is(err, ErrClosed) {
		t.Fatalf("closed queue = %t, %v", queued, err)
	}
}
