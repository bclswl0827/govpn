package packet

import "context"

// Inject queues a gVisor packet for the VPN engine.
func (d *Device) Inject(ctx context.Context, packet []byte) error {
	if d.closedFlag.Load() {
		return ErrClosed
	}
	owned := append([]byte(nil), packet...)
	select {
	case d.toProtocol <- owned:
		return nil
	case <-d.closed:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Receive returns a decrypted packet for injection into gVisor.
func (d *Device) Receive(ctx context.Context) ([]byte, error) {
	if d.closedFlag.Load() {
		return nil, ErrClosed
	}
	select {
	case packet := <-d.fromProtocol:
		return packet, nil
	case <-d.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReadPacket and WritePacket are single-packet methods for stream protocols.
func (d *Device) ReadPacket(ctx context.Context) ([]byte, error) {
	if d.closedFlag.Load() {
		return nil, ErrClosed
	}
	select {
	case packet := <-d.toProtocol:
		return packet, nil
	case <-d.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *Device) WritePacket(ctx context.Context, packet []byte) error {
	if d.closedFlag.Load() {
		return ErrClosed
	}
	owned := append([]byte(nil), packet...)
	select {
	case d.fromProtocol <- owned:
		return nil
	case <-d.closed:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryWritePacket queues a decrypted IP packet without blocking the transport's
// control/keepalive reader. A full queue drops data and lets inner TCP recover.
// The bool reports whether the packet was queued; only closure returns an error.
func (d *Device) TryWritePacket(packet []byte) (bool, error) {
	if d.closedFlag.Load() {
		return false, ErrClosed
	}
	owned := append([]byte(nil), packet...)
	select {
	case <-d.closed:
		return false, ErrClosed
	case d.fromProtocol <- owned:
		return true, nil
	default:
		d.inboundDrops.Add(1)
		return false, nil
	}
}

// QueueStats returns instantaneous queue depths and cumulative congestion drops.
func (d *Device) QueueStats() (outbound, inbound int, inboundDrops uint64) {
	return len(d.toProtocol), len(d.fromProtocol), d.inboundDrops.Load()
}

// TryInject enqueues a packet without blocking. Shared multi-peer routers use
// this to isolate slow peers; IP transports may drop packets under congestion.
func (d *Device) TryInject(packet []byte) bool {
	if d.closedFlag.Load() {
		return false
	}
	owned := append([]byte(nil), packet...)
	select {
	case <-d.closed:
		return false
	default:
	}
	select {
	case d.toProtocol <- owned:
		return true
	default:
		return false
	}
}
