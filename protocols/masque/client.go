package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
)

type Client struct {
	Config  Config
	mu      sync.Mutex
	runtime *clientRuntime
}

func NewClient(config Config) *Client { return &Client{Config: config} }

var _ govpn.Client = (*Client)(nil)

// ErrHTTPVersionUnavailable identifies transport/protocol negotiation failures
// eligible for version fallback. HTTP status and certificate failures are not.
var ErrHTTPVersionUnavailable = errors.New("masque: HTTP version unavailable")

func fallbackError(err error) bool {
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return false
	}
	if errors.Is(err, ErrHTTPVersionUnavailable) {
		return true
	}
	var network net.Error
	if errors.As(err, &network) {
		return true
	}
	return strings.Contains(err.Error(), "no application protocol")
}

func establish(ctx context.Context, c Config) (*tunnel, int, error) {
	d, mtu, _, err := prepareClient(c)
	if err != nil {
		return nil, 0, err
	}
	for version := d.Version; version >= 1; version-- {
		attempt := c
		attempt.Version = version
		if version != 3 {
			attempt.HTTP3 = HTTP3Options{}
		}
		if version == 1 {
			if c.Protocol != "" && c.Protocol != "connect-ip" {
				break
			}
			attempt.AllowMissingExtendedConnect = false
		}
		current, _, addresses, err := prepareClient(attempt)
		if err != nil {
			return nil, 0, err
		}
		handshake, cancel := context.WithTimeout(ctx, 30*time.Second)
		dialer := c.Dialer
		if dialer == nil {
			dialer = DefaultTunnelDialer{}
		}
		conn, dialErr := dialer.DialTunnel(handshake, current)
		if dialErr != nil || conn == nil {
			if conn != nil {
				conn.Close()
			}
			cancel()
			if dialErr == nil {
				dialErr = errors.New("masque: dialer returned nil tunnel")
			}
			err = fmt.Errorf("masque: HTTP/%d tunnel: %w", version, dialErr)
			if c.DisableVersionFallback || ctx.Err() != nil || !fallbackError(dialErr) || version == 1 {
				return nil, 0, err
			}
			continue
		}
		stop := context.AfterFunc(handshake, func() { conn.Close() })
		t := &tunnel{conn: conn, reader: bufio.NewReader(conn), addresses: addresses}
		t.advertised, _ = routesFromPrefixes(c.AdvertiseRoutes)
		setupErr := func() error {
			if len(addresses) == 0 {
				if err := t.write(capsuleRequest, encodeAddresses([]assignedAddress{{id: 1, prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 32)}, {id: 2, prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 128)}})); err != nil {
					return err
				}
			}
			if len(t.advertised) > 0 {
				if err := t.write(capsuleRoutes, encodeRanges(t.advertised)); err != nil {
					return err
				}
			}
			for len(localAddresses(t.addresses)) == 0 {
				kind, payload, err := readCapsule(t.reader)
				if err != nil {
					return fmt.Errorf("masque: address negotiation: %w", err)
				}
				if kind == capsuleAssign {
					t.addresses, err = parseAddresses(payload)
				} else if kind != capsuleDatagram {
					err = t.control(kind, payload)
				}
				if err != nil {
					return err
				}
			}
			return nil
		}()
		stopped := stop()
		cancel()
		if setupErr != nil || !stopped || ctx.Err() != nil {
			conn.Close()
			if setupErr != nil {
				return nil, 0, setupErr
			}
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			return nil, 0, context.DeadlineExceeded
		}
		return t, mtu, nil
	}
	return nil, 0, ErrHTTPVersionUnavailable
}

type clientRuntime struct {
	ctx                       context.Context
	cancel                    context.CancelFunc
	config                    Config
	device                    *packet.Device
	session                   *govpn.Session
	mu                        sync.Mutex
	active                    *tunnel
	queue                     *packet.Device
	cancelPeer                context.CancelFunc
	suspended, restart, ready bool
	lastErr                   error
	changed                   chan struct{}
	configuration             Configuration
	once                      sync.Once
}

func (r *clientRuntime) notify() { close(r.changed); r.changed = make(chan struct{}) }
func (r *clientRuntime) close() error {
	r.once.Do(func() {
		r.cancel()
		r.mu.Lock()
		if r.cancelPeer != nil {
			r.cancelPeer()
		}
		if r.active != nil {
			r.active.conn.Close()
		}
		r.ready = false
		r.configuration.Ready = false
		r.notify()
		r.mu.Unlock()
		r.device.Close()
	})
	return nil
}

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	if c.runtime != nil && c.runtime.ctx.Err() == nil {
		return nil, errors.New("masque: client already started")
	}
	t, mtu, err := establish(ctx, c.Config)
	if err != nil {
		return nil, err
	}
	device, err := packet.New("masque-client", mtu)
	if err != nil {
		t.conn.Close()
		return nil, err
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	r := &clientRuntime{ctx: runtimeCtx, cancel: cancel, config: c.Config, device: device, changed: make(chan struct{})}
	done := make(chan error, 1)
	session, err := govpn.NewSession(localAddresses(t.addresses), uint32(mtu), device, r.close, done)
	if err != nil {
		t.conn.Close()
		cancel()
		return nil, err
	}
	r.session = session
	c.runtime = r
	c.mu.Unlock()
	locked = false
	r.attach(t)
	go r.dispatch()
	go func() { done <- r.loop(t, mtu) }()
	for {
		r.mu.Lock()
		active, changed := r.active != nil && r.ready, r.changed
		r.mu.Unlock()
		if active {
			return session, nil
		}
		select {
		case <-changed:
		case <-r.ctx.Done():
			session.Close()
			return nil, r.ctx.Err()
		}
	}
}
func (r *clientRuntime) attach(t *tunnel) {
	t.onAssign = func(addresses []assignedAddress) error {
		next := localAddresses(addresses)
		if err := r.session.UpdateAddresses(next); err != nil {
			return err
		}
		t.stateMu.Lock()
		t.addresses = append([]assignedAddress(nil), addresses...)
		t.stateMu.Unlock()
		r.publish(t)
		return nil
	}
	t.onRoutes = func(routes []addressRange) error {
		t.stateMu.Lock()
		t.routes = routes
		t.routesAdvertised = true
		t.stateMu.Unlock()
		r.publish(t)
		return nil
	}
	t.onPacket = func(ctx context.Context, p []byte) error {
		_, destination, valid := packetAddresses(p)
		if !valid {
			return nil
		}
		t.stateMu.RLock()
		local := containsAddress(t.addresses, destination)
		advertised := containsRoute(t.advertised, destination, 0)
		addresses := localAddresses(t.addresses)
		t.stateMu.RUnlock()
		if !local && !advertised {
			if reply := icmpError(p, noRoute, addresses, 0); reply != nil {
				return t.write(capsuleDatagram, append([]byte{0}, reply...))
			}
			return nil
		}
		if !local && r.config.ForwardPacket != nil {
			return r.config.ForwardPacket(ctx, append([]byte(nil), p...))
		}
		return r.device.WritePacket(ctx, p)
	}
	t.filterOutbound = func(ctx context.Context, p []byte) (bool, error) {
		_, destination, valid := packetAddresses(p)
		proto, ok := packetProtocol(p)
		if !valid || !ok {
			return false, nil
		}
		t.stateMu.RLock()
		allowed := !t.routesAdvertised || containsRoute(t.routes, destination, proto)
		addresses := localAddresses(t.addresses)
		t.stateMu.RUnlock()
		if !allowed {
			if reply := icmpError(p, noRoute, addresses, 0); reply != nil {
				return false, r.deliverReply(t, ctx, reply)
			}
		}
		return allowed, nil
	}
	t.onTooBig = func(ctx context.Context, p []byte, mtu int) error {
		t.stateMu.RLock()
		addresses := localAddresses(t.addresses)
		t.stateMu.RUnlock()
		if reply := icmpError(p, packetTooBig, addresses, mtu); reply != nil {
			return r.deliverReply(t, ctx, reply)
		}
		return nil
	}
}
func (r *clientRuntime) publish(t *tunnel) {
	t.stateMu.RLock()
	snapshot := Configuration{Addresses: localAddresses(t.addresses), Routes: publicRoutes(t.routes), RoutesAdvertised: t.routesAdvertised}
	t.stateMu.RUnlock()
	r.mu.Lock()
	snapshot.Ready = len(snapshot.Addresses) > 0 && !r.suspended && !r.restart && r.active == t && r.ctx.Err() == nil
	r.ready = snapshot.Ready
	r.configuration = snapshot
	r.lastErr = nil
	r.notify()
	r.mu.Unlock()
	if r.config.ConfigurationChanged != nil {
		snapshot.Addresses = append([]netip.Prefix(nil), snapshot.Addresses...)
		snapshot.Routes = append([]Route(nil), snapshot.Routes...)
		r.config.ConfigurationChanged(snapshot)
	}
}
func (r *clientRuntime) dispatch() {
	for {
		p, err := r.device.ReadPacket(r.ctx)
		if err != nil {
			return
		}
		r.mu.Lock()
		q, ready := r.queue, r.ready
		r.mu.Unlock()
		if q != nil && ready {
			_ = q.Inject(r.ctx, p)
		}
	}
}
func (r *clientRuntime) loop(first *tunnel, mtu int) error {
	defer r.close()
	initial, maximum := r.config.ReconnectInitial, r.config.ReconnectMax
	if initial == 0 {
		initial = time.Second
	}
	if maximum == 0 {
		maximum = time.Minute
	}
	if maximum < initial {
		maximum = initial
	}
	backoff := initial
	t := first
	for {
		if t != nil {
			peerCtx, cancel := context.WithCancel(r.ctx)
			q, err := packet.New("masque-peer", mtu)
			if err != nil {
				t.conn.Close()
				return err
			}
			r.mu.Lock()
			r.active = t
			r.queue = q
			r.cancelPeer = cancel
			r.notify()
			if r.suspended || r.restart {
				cancel()
			}
			r.mu.Unlock()
			r.publish(t)
			err = t.run(peerCtx, q)
			cancel()
			q.Close()
			r.mu.Lock()
			r.active = nil
			r.queue = nil
			r.cancelPeer = nil
			r.ready = false
			r.configuration.Ready = false
			r.lastErr = err
			interrupted := r.suspended || r.restart
			r.restart = false
			r.notify()
			r.mu.Unlock()
			if r.ctx.Err() != nil {
				return nil
			}
			if r.config.DisableReconnect && !interrupted {
				return err
			}
			if r.config.Logger != nil {
				r.config.Logger.Printf("[masque] tunnel disconnected: %v", err)
			}
			t = nil
			backoff = initial
			if interrupted {
				backoff = 0
			}
		}
		r.mu.Lock()
		suspended, changed := r.suspended, r.changed
		if r.restart {
			backoff = 0
		}
		r.mu.Unlock()
		if suspended {
			select {
			case <-changed:
				continue
			case <-r.ctx.Done():
				return nil
			}
		}
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-changed:
			timer.Stop()
			continue
		case <-r.ctx.Done():
			timer.Stop()
			return nil
		}
		r.mu.Lock()
		if r.suspended {
			r.mu.Unlock()
			continue
		}
		dialCtx, cancel := context.WithCancel(r.ctx)
		r.cancelPeer = cancel
		r.restart = false
		r.mu.Unlock()
		next, _, err := establish(dialCtx, r.config)
		cancel()
		r.mu.Lock()
		r.cancelPeer = nil
		interrupted := r.suspended || r.restart
		r.restart = false
		r.lastErr = err
		r.notify()
		r.mu.Unlock()
		if r.ctx.Err() != nil {
			if next != nil {
				next.conn.Close()
			}
			return nil
		}
		if interrupted {
			if next != nil {
				next.conn.Close()
			}
			backoff = 0
			continue
		}
		if err != nil {
			backoff = min(max(initial, backoff*2), maximum)
			continue
		}
		if err := r.session.UpdateAddresses(localAddresses(next.addresses)); err != nil {
			next.conn.Close()
			return err
		}
		r.attach(next)
		t = next
	}
}
func (c *Client) getRuntime() *clientRuntime { c.mu.Lock(); defer c.mu.Unlock(); return c.runtime }
func (c *Client) Ready() bool {
	r := c.getRuntime()
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ready && r.active != nil && r.ctx.Err() == nil
}
func (c *Client) WaitReady(ctx context.Context) error {
	r := c.getRuntime()
	if r == nil {
		return errors.New("masque: client not started")
	}
	for {
		r.mu.Lock()
		ready, changed := r.ready && r.active != nil, r.changed
		r.mu.Unlock()
		if r.ctx.Err() != nil {
			return net.ErrClosed
		}
		if ready {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-r.ctx.Done():
			return net.ErrClosed
		}
	}
}
func (c *Client) Suspend() {
	r := c.getRuntime()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.suspended = true
	r.restart = true
	r.ready = false
	r.configuration.Ready = false
	if r.cancelPeer != nil {
		r.cancelPeer()
	}
	r.notify()
	r.mu.Unlock()
}
func (c *Client) Resume() {
	r := c.getRuntime()
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.suspended {
		r.suspended = false
		r.notify()
	}
	r.mu.Unlock()
}
func (c *Client) RestartSession() {
	r := c.getRuntime()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.restart = true
	r.ready = false
	r.configuration.Ready = false
	if r.cancelPeer != nil {
		r.cancelPeer()
	}
	r.notify()
	r.mu.Unlock()
}
func (c *Client) Configuration() Configuration {
	r := c.getRuntime()
	if r == nil {
		return Configuration{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.configuration
	out.Addresses = append([]netip.Prefix(nil), out.Addresses...)
	out.Routes = append([]Route(nil), out.Routes...)
	return out
}

// WritePacket sends a forwarded IP packet into the active tunnel, decrementing
// its hop limit. The input is copied; source addresses must be owned/advertised.
func (c *Client) WritePacket(ctx context.Context, p []byte) error {
	r := c.getRuntime()
	if r == nil {
		return net.ErrClosed
	}
	source, _, ok := packetAddresses(p)
	if !ok {
		return errors.New("masque: invalid IP packet")
	}
	r.mu.Lock()
	q, ready, active := r.queue, r.ready, r.active
	r.mu.Unlock()
	if q == nil || !ready || active == nil {
		return errors.New("masque: tunnel not ready")
	}
	active.stateMu.RLock()
	owned := containsAddress(active.addresses, source) || containsRoute(active.advertised, source, 0)
	addresses := localAddresses(active.addresses)
	active.stateMu.RUnlock()
	if !owned {
		return errors.New("masque: forwarded source is not assigned or advertised")
	}
	p = append([]byte(nil), p...)
	if !decrementHopLimit(p) {
		if reply := icmpError(p, hopLimitExceeded, addresses, 0); reply != nil {
			return r.deliverReply(active, ctx, reply)
		}
		return nil
	}
	return q.Inject(ctx, p)
}

// DialContext is the readiness-aware socket API. OnDemand resumes a suspended
// tunnel; other clients fail immediately while disconnected.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r := c.getRuntime()
	if r == nil {
		return nil, net.ErrClosed
	}
	if r.config.OnDemand {
		c.Resume()
		if err := c.WaitReady(ctx); err != nil {
			return nil, err
		}
	} else if !c.Ready() {
		return nil, errors.New("masque: tunnel not ready")
	}
	return r.session.DialContext(ctx, network, address)
}
func (c *Client) ListenPacket(network, address string) (net.PacketConn, error) {
	r := c.getRuntime()
	if r == nil {
		return nil, net.ErrClosed
	}
	return r.session.ListenPacket(network, address)
}
func (c *Client) Wait(ctx context.Context) error {
	r := c.getRuntime()
	if r == nil {
		return net.ErrClosed
	}
	return r.session.Wait(ctx)
}
func (c *Client) Close() error {
	r := c.getRuntime()
	if r == nil {
		return nil
	}
	return r.session.Close()
}

// Listen opens a listener on the persistent userspace Session.
func (c *Client) Listen(network, address string) (net.Listener, error) {
	r := c.getRuntime()
	if r == nil {
		return nil, net.ErrClosed
	}
	return r.session.Listen(network, address)
}

// Return locally generated errors through the same userspace boundary as data.
func (r *clientRuntime) deliverReply(t *tunnel, ctx context.Context, p []byte) error {
	_, destination, valid := packetAddresses(p)
	if !valid {
		return nil
	}
	t.stateMu.RLock()
	local := containsAddress(t.addresses, destination)
	t.stateMu.RUnlock()
	if !local && r.config.ForwardPacket != nil {
		return r.config.ForwardPacket(ctx, p)
	}
	return r.device.WritePacket(ctx, p)
}
