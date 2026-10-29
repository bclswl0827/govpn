package packet

import (
	"errors"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

var ErrClosed = errors.New("packet device closed")

const queueSize = 1024

// Device presents opposite views of the same packet queues. VPN engines use
// the tun.Device-compatible Read/Write methods. gVisor uses Inject/Receive.
type Device struct {
	name string
	mtu  int

	toProtocol   chan []byte
	fromProtocol chan []byte
	events       chan tun.Event
	closed       chan struct{}
	closedFlag   atomic.Bool
	inboundDrops atomic.Uint64
	closeOnce    sync.Once
}

func New(name string, mtu int) (*Device, error) {
	if name == "" {
		return nil, errors.New("packet device name is required")
	}
	if mtu <= 0 || mtu > 65535 {
		return nil, errors.New("packet device MTU is out of range")
	}
	d := &Device{
		name:         name,
		mtu:          mtu,
		toProtocol:   make(chan []byte, queueSize),
		fromProtocol: make(chan []byte, queueSize),
		events:       make(chan tun.Event, 1),
		closed:       make(chan struct{}),
	}
	d.events <- tun.EventUp
	return d, nil
}

func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.closedFlag.Store(true)
		close(d.closed)
		close(d.events)
	})
	return nil
}
