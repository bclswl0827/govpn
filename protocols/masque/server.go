package masque

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/netutil"
	"github.com/bclswl0827/govpn/internal/packet"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Server struct {
	Config    ServerConfig
	mu        sync.Mutex
	transport *serverTransport
}

func NewServer(config ServerConfig) *Server { return &Server{Config: config} }

var _ govpn.Server = (*Server)(nil)

type serverTransport struct {
	ctx           context.Context
	cancel        context.CancelFunc
	closers       []io.Closer
	device        *packet.Device
	mu            sync.Mutex
	peers         map[*serverPeer]struct{}
	pools         []*addressPool
	local         []netip.Prefix
	forwardPacket func(context.Context, []byte) error
	sequence      uint64
	closed        bool
	once          sync.Once
}

func (s *serverTransport) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.mu.Lock()
		s.closed = true
		peers := make([]*serverPeer, 0, len(s.peers))
		for p := range s.peers {
			peers = append(peers, p)
		}
		s.mu.Unlock()
		for _, p := range peers {
			if p.tunnel != nil {
				p.tunnel.conn.Close()
			}
			if p.queue != nil {
				p.queue.Close()
			}
		}
		for _, closer := range s.closers {
			_ = closer.Close()
		}
		_ = s.device.Close()
	})
	return nil
}

func (s *Server) Start(ctx context.Context) (*govpn.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transport != nil && s.transport.ctx.Err() == nil {
		return nil, errors.New("masque: server already started")
	}
	template, err := parseTemplate(s.Config.Path)
	if err != nil {
		return nil, err
	}
	_, mtu, err := options(DefaultPath, s.Config.MTU)
	if err != nil {
		return nil, err
	}
	if s.Config.ListenPort < 1 || s.Config.ListenPort > 65535 {
		return nil, errors.New("masque: listen port is out of range")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.Config.TLSConfig != nil {
		tlsConfig = s.Config.TLSConfig.Clone()
	}
	if len(s.Config.Cert) > 0 || len(s.Config.Key) > 0 {
		certificate, err := tls.X509KeyPair(s.Config.Cert, s.Config.Key)
		if err != nil {
			return nil, fmt.Errorf("masque: server certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil {
		return nil, errors.New("masque: server TLS certificate is required")
	}
	var pools []*addressPool
	local := append([]netip.Prefix(nil), s.Config.Address...)
	if len(local) > 0 && (s.Config.Pool != "" || s.Config.IPv6Pool != "") {
		return nil, errors.New("masque: Address and Pool/IPv6Pool are mutually exclusive")
	}
	if len(local) == 0 {
		for i, value := range []string{s.Config.Pool, s.Config.IPv6Pool} {
			if value == "" {
				continue
			}
			parse := netutil.ParseIPv4Pool
			if i == 1 {
				parse = netutil.ParseIPv6Pool
			}
			pool, gateway, _, err := parse(value)
			if err != nil {
				return nil, err
			}
			local = append(local, netip.PrefixFrom(gateway, pool.Bits()))
		}
	}
	if len(local) == 0 {
		return nil, errors.New("masque: at least one server address/pool is required")
	}
	families := make(map[int]bool)
	var prefixes []netip.Prefix
	for _, address := range local {
		if families[address.Addr().BitLen()] {
			return nil, errors.New("masque: at most one server address per IP family")
		}
		families[address.Addr().BitLen()] = true
		pool, err := newAddressPool(address)
		if err != nil {
			return nil, err
		}
		pools = append(pools, pool)
		prefixes = append(prefixes, address.Masked())
	}
	routes := append([]netip.Prefix(nil), s.Config.AdvertiseRoutes...)
	if len(routes) == 0 {
		routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	routes = append(routes, prefixes...)
	allowed, err := routesFromPrefixes(routes)
	if err != nil {
		return nil, err
	}
	resolve := s.Config.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	versions := make(map[int]bool)
	configured := s.Config.Versions
	if len(configured) == 0 {
		configured = []int{1, 2, 3}
	}
	for _, version := range configured {
		if version < 1 || version > 3 {
			return nil, errors.New("masque: HTTP version must be 1, 2, or 3")
		}
		versions[version] = true
	}
	device, err := packet.New("masque-server", mtu)
	if err != nil {
		return nil, err
	}
	transportCtx, cancel := context.WithCancel(ctx)
	t := &serverTransport{ctx: transportCtx, cancel: cancel, device: device, peers: make(map[*serverPeer]struct{}), pools: pools, local: local, forwardPacket: s.Config.ForwardPacket}
	success := false
	defer func() {
		if !success {
			_ = t.Close()
		}
	}()
	users := make(map[string]string, len(s.Config.Users))
	for name, password := range s.Config.Users {
		users[name] = password
	}
	logger := s.Config.Logger
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope, matched, err := template.match(r.URL)
		if !matched {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "Invalid scope", 400)
			return
		}
		valid := versions[r.ProtoMajor] && r.Header.Get("Capsule-Protocol") == "?1"
		if r.ProtoMajor == 1 {
			valid = valid && r.Method == http.MethodGet && r.ProtoMinor == 1 && upgradeHeader(r.Header) && r.ContentLength <= 0 && len(r.TransferEncoding) == 0
		} else {
			valid = valid && r.Method == http.MethodConnect && r.Proto == "connect-ip"
		}
		if !valid {
			http.Error(w, "CONNECT-IP required", http.StatusBadRequest)
			return
		}
		if len(users) > 0 {
			username, password, ok := r.BasicAuth()
			expected, exists := users[username]
			if !ok || !exists || subtle.ConstantTimeCompare([]byte(password), []byte(expected)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="masque", charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		var targets []netip.Prefix
		if scope.target != "*" {
			if prefix, err := targetPrefix(scope.target); err == nil {
				targets = append(targets, prefix)
			} else {
				if strings.ContainsAny(scope.target, ":/") {
					http.Error(w, "Invalid target", 400)
					return
				}
				resolveCtx, resolveCancel := context.WithTimeout(r.Context(), 30*time.Second)
				addresses, err := resolve(resolveCtx, scope.target)
				resolveCancel()
				if err != nil || len(addresses) == 0 {
					http.Error(w, "Target resolution failed", 502)
					return
				}
				for _, a := range addresses {
					a = a.Unmap()
					if a.IsValid() && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() {
						targets = append(targets, netip.PrefixFrom(a, a.BitLen()))
					}
				}
			}
			if len(targets) == 0 {
				http.Error(w, "Target resolution returned no usable addresses", 502)
				return
			}
		}
		p := &serverPeer{}
		for _, pool := range pools {
			if a, ok := pool.allocate(); ok {
				p.assigned = append(p.assigned, assignedAddress{prefix: netip.PrefixFrom(a, a.BitLen())})
			}
		}
		defer t.release(p)
		if len(p.assigned) == 0 {
			http.Error(w, "Address pool exhausted", http.StatusServiceUnavailable)
			return
		}
		p.allowed = scopeRoutes(allowed, targets, scope.protocol, p.assigned)
		if len(p.allowed) == 0 {
			http.Error(w, "Target not permitted", http.StatusForbidden)
			return
		}
		handshakeCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		conn, err := acceptTunnel(handshakeCtx, w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		queue, err := packet.New("masque-server-peer", mtu)
		if err != nil {
			return
		}
		p.queue = queue
		peer := &tunnel{conn: conn, reader: bufio.NewReader(conn), addresses: p.assigned, server: true}
		p.tunnel = peer
		peer.onRoutes = func(routes []addressRange) error {
			peer.stateMu.Lock()
			peer.routes = routes
			peer.routesAdvertised = true
			peer.stateMu.Unlock()
			t.mu.Lock()
			t.sequence++
			p.order = t.sequence
			t.mu.Unlock()
			return nil
		}
		peer.onPacket = func(ctx context.Context, packet []byte) error { return t.inbound(ctx, p, packet) }
		peer.onTooBig = func(ctx context.Context, packet []byte, mtu int) error {
			return t.reply(ctx, packet, packetTooBig, nil, mtu)
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return
		}
		t.peers[p] = struct{}{}
		t.sequence++
		p.order = t.sequence
		t.mu.Unlock()
		stop := context.AfterFunc(handshakeCtx, func() { conn.Close() })
		defer stop()
		err = peer.write(capsuleAssign, encodeAddresses(p.assigned))
		if err == nil {
			err = peer.write(capsuleRoutes, encodeRanges(p.allowed))
		}
		if err == nil && stop() {
			p.ready.Store(true)
			if logger != nil {
				logger.Printf("[masque] HTTP/%d client connected: remote=%s addresses=%v", r.ProtoMajor, r.RemoteAddr, localAddresses(p.assigned))
			}
			err = peer.run(t.ctx, queue)
		}
		if logger != nil {
			logger.Printf("[masque] client disconnected: %v", err)
		}
	})
	address := net.JoinHostPort(s.Config.ListenIP, strconv.Itoa(s.Config.ListenPort))
	tlsConfig.NextProtos = nil
	var serve []func() error
	if versions[1] || versions[2] {
		if versions[2] {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
		}
		if versions[1] {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
		}
		listener, err := tls.Listen("tcp", address, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("masque: TCP listen: %w", err)
		}
		httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler))}
		if versions[2] {
			httpServer.TLSNextProto["h2"] = func(_ *http.Server, conn *tls.Conn, _ http.Handler) { serveHTTP2(t.ctx, conn, handler) }
		}
		t.closers = append(t.closers, listener, httpServer)
		serve = append(serve, func() error { return httpServer.Serve(listener) })
	}
	if versions[3] {
		config := tlsConfig.Clone()
		config.NextProtos = []string{http3.NextProtoH3}
		prepared, _, _, err := prepareClient(Config{Server: "localhost", Version: 3, MTU: mtu, HTTP3: s.Config.HTTP3})
		if err != nil {
			return nil, err
		}
		socket, err := net.ListenPacket("udp", address)
		if err != nil {
			return nil, err
		}
		transport := &quic.Transport{Conn: socket, ConnectionIDLength: prepared.HTTP3.ConnectionIDLength}
		t.closers = append(t.closers, socket, transport)
		listener, err := transport.ListenEarly(config, prepared.HTTP3.QUICConfig)
		if err != nil {
			return nil, fmt.Errorf("masque: QUIC listen: %w", err)
		}
		httpServer := &http3.Server{Handler: handler, EnableDatagrams: true, MaxHeaderBytes: 16 << 10, AdditionalSettings: prepared.HTTP3.AdditionalSettings}
		t.closers = append(t.closers, listener, httpServer)
		serve = append(serve, func() error { return httpServer.ServeListener(listener) })
	}
	done := make(chan error, 1)
	session, err := govpn.NewSession(local, uint32(mtu), device, t.Close, done)
	if err != nil {
		return nil, err
	}
	go func() {
		stop := context.AfterFunc(t.ctx, func() { _ = t.Close() })
		defer stop()
		results := make(chan error, len(serve))
		for _, run := range serve {
			go func() { results <- run() }()
		}
		err := <-results
		if t.ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		_ = t.Close()
		for i := 1; i < len(serve); i++ {
			<-results
		}
		done <- err
	}()
	s.transport = t
	go t.dispatch()
	success = true
	return session, nil
}

func acceptTunnel(ctx context.Context, w http.ResponseWriter, r *http.Request) (io.ReadWriteCloser, error) {
	switch r.ProtoMajor {
	case 1:
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\nCapsule-Protocol: ?1\r\n\r\n")
		if err == nil {
			err = rw.Flush()
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return &bufferedStream{ReadWriteCloser: conn, reader: rw.Reader}, nil
	case 2:
		response, ok := w.(*h2Response)
		if !ok {
			return nil, errors.New("masque: HTTP/2 stream unavailable")
		}
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		if err := response.FlushError(); err != nil {
			return nil, err
		}
		return response.stream, nil
	case 3:
		return acceptHTTP3(ctx, w)
	default:
		return nil, errors.New("masque: unsupported HTTP version")
	}
}
