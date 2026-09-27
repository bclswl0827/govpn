package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2Stream uses one CONNECT stream per TLS connection. Framer and HPACK are
// public APIs; no process-wide GODEBUG, linkname, or Go-version build tags are
// needed to advertise SETTINGS_ENABLE_CONNECT_PROTOCOL.
// The receive buffer is bounded by the 65535-byte advertised flow window.
type h2Stream struct {
	conn                                net.Conn
	framer                              *http2.Framer
	writeMu                             sync.Mutex
	mu                                  sync.Mutex
	cond                                *sync.Cond
	data                                bytes.Buffer
	err                                 error
	eof                                 bool
	id                                  uint32
	sendConn, sendStream, initialWindow int64
	recvWindow                          int64
	maxFrame                            int
	headers                             chan *http2.MetaHeadersFrame
	settings                            chan struct{}
	done                                chan struct{}
	closeOnce                           sync.Once
	gotSettings                         bool
	extended                            bool
	server                              bool
}

func newH2Stream(conn net.Conn, server bool) (*h2Stream, error) {
	s := &h2Stream{conn: conn, server: server, sendConn: 65535, sendStream: 65535,
		initialWindow: 65535, recvWindow: 65535, maxFrame: 16384,
		headers: make(chan *http2.MetaHeadersFrame, 1), settings: make(chan struct{}), done: make(chan struct{})}
	if !server {
		s.id = 1
	}
	s.cond = sync.NewCond(&s.mu)
	s.framer = http2.NewFramer(conn, conn)
	s.framer.SetMaxReadFrameSize(16384)
	s.framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	s.framer.MaxHeaderListSize = 16 << 10
	if server {
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			return nil, err
		}
		if string(preface) != http2.ClientPreface {
			return nil, errors.New("masque: invalid HTTP/2 preface")
		}
	} else if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return nil, err
	}
	settings := []http2.Setting{{ID: http2.SettingMaxConcurrentStreams, Val: 1}, {ID: http2.SettingMaxHeaderListSize, Val: 16 << 10}}
	if server {
		settings = append(settings, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
	} else {
		settings = append(settings, http2.Setting{ID: http2.SettingEnablePush, Val: 0})
	}
	if err := s.framer.WriteSettings(settings...); err != nil {
		return nil, err
	}
	go func() { s.fail(s.readFrames()) }()
	return s, nil
}

func (s *h2Stream) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.cond.Broadcast()
	s.closeOnce.Do(func() { close(s.done) })
	s.mu.Unlock()
	_ = s.conn.Close()
}
func (s *h2Stream) Close() error { s.fail(net.ErrClosed); return nil }

func (s *h2Stream) frame(fn func() error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return fn()
}

func (s *h2Stream) readFrames() error {
	seenHeaders := false
	for {
		f, err := s.framer.ReadFrame()
		if err != nil {
			return err
		}
		if !s.gotSettings {
			settings, ok := f.(*http2.SettingsFrame)
			if !ok || settings.IsAck() {
				return errors.New("masque: HTTP/2 first frame must be SETTINGS")
			}
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			s.mu.Lock()
			err := f.ForeachSetting(func(v http2.Setting) error {
				if err := v.Valid(); err != nil {
					return err
				}
				switch v.ID {
				case http2.SettingInitialWindowSize:
					s.sendStream += int64(v.Val) - s.initialWindow
					s.initialWindow = int64(v.Val)
					if s.sendStream > 1<<31-1 {
						return errors.New("masque: HTTP/2 flow window overflow")
					}
				case http2.SettingMaxFrameSize:
					s.maxFrame = int(v.Val)
				case http2.SettingEnableConnectProtocol:
					s.extended = v.Val == 1
				}
				return nil
			})
			s.cond.Broadcast()
			s.mu.Unlock()
			if err != nil {
				return err
			}
			if !s.gotSettings {
				s.gotSettings = true
				close(s.settings)
			}
			if err := s.frame(s.framer.WriteSettingsAck); err != nil {
				return err
			}
		case *http2.MetaHeadersFrame:
			if f.Truncated {
				return errors.New("masque: HTTP/2 headers exceed 16 KiB")
			}
			s.mu.Lock()
			if s.server && s.id == 0 {
				s.id = f.StreamID
			}
			id := s.id
			s.mu.Unlock()
			if f.StreamID != id {
				if !s.server || f.StreamID%2 != 1 {
					return errors.New("masque: invalid HTTP/2 stream ID")
				}
				if err := s.frame(func() error { return s.framer.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream) }); err != nil {
					return err
				}
				continue
			}
			if f.StreamID%2 != 1 {
				return errors.New("masque: invalid CONNECT stream ID")
			}
			if seenHeaders {
				if !f.StreamEnded() || len(f.PseudoFields()) != 0 {
					return errors.New("masque: invalid HTTP/2 trailers")
				}
			} else {
				// Ignore informational responses, but never HTTP/1.1 Upgrade responses.
				status, _ := strconv.Atoi(f.PseudoValue("status"))
				if !s.server && status >= 100 && status < 200 {
					if status == 101 || f.StreamEnded() {
						return errors.New("masque: invalid HTTP/2 informational response")
					}
					continue
				}
				seenHeaders = true
				snapshot := *f
				header := *f.HeadersFrame
				snapshot.HeadersFrame = &header
				snapshot.Fields = append([]hpack.HeaderField(nil), f.Fields...)
				s.headers <- &snapshot
			}
			if f.StreamEnded() {
				s.mu.Lock()
				s.eof = true
				s.cond.Broadcast()
				s.mu.Unlock()
			}
		case *http2.DataFrame:
			s.mu.Lock()
			if !seenHeaders || f.StreamID != s.id || s.eof || int64(f.Length) > s.recvWindow {
				s.mu.Unlock()
				return errors.New("masque: invalid HTTP/2 DATA or receive window exceeded")
			}
			s.recvWindow -= int64(f.Length)
			_, _ = s.data.Write(f.Data())
			if f.StreamEnded() {
				s.eof = true
			}
			s.cond.Broadcast()
			s.mu.Unlock()
			if padding := int(f.Length) - len(f.Data()); padding > 0 {
				if err := s.credit(padding); err != nil {
					return err
				}
			}
		case *http2.WindowUpdateFrame:
			s.mu.Lock()
			var window *int64
			if f.StreamID == 0 {
				window = &s.sendConn
			} else if f.StreamID == s.id {
				window = &s.sendStream
			}
			if window != nil {
				*window += int64(f.Increment)
			}
			overflow := window != nil && *window > 1<<31-1
			s.cond.Broadcast()
			s.mu.Unlock()
			if overflow {
				return errors.New("masque: HTTP/2 flow window overflow")
			}
		case *http2.PingFrame:
			if !f.Flags.Has(http2.FlagPingAck) {
				if err := s.frame(func() error { return s.framer.WritePing(true, f.Data) }); err != nil {
					return err
				}
			}
		case *http2.RSTStreamFrame:
			s.mu.Lock()
			id := s.id
			s.mu.Unlock()
			if f.StreamID == id {
				return fmt.Errorf("masque: HTTP/2 stream reset: %v", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			s.mu.Lock()
			id := s.id
			s.mu.Unlock()
			if f.ErrCode != http2.ErrCodeNo || f.LastStreamID < id {
				return fmt.Errorf("masque: HTTP/2 GOAWAY: %v", f.ErrCode)
			}
		case *http2.PushPromiseFrame:
			return errors.New("masque: HTTP/2 server push is disabled")
		}
	}
}

func (s *h2Stream) credit(n int) error {
	s.mu.Lock()
	s.recvWindow += int64(n)
	id := s.id
	s.mu.Unlock()
	return s.frame(func() error {
		if err := s.framer.WriteWindowUpdate(0, uint32(n)); err != nil {
			return err
		}
		return s.framer.WriteWindowUpdate(id, uint32(n))
	})
}

func (s *h2Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	for s.data.Len() == 0 && s.err == nil && !s.eof {
		s.cond.Wait()
	}
	if s.data.Len() == 0 {
		err := s.err
		if err == nil {
			err = io.EOF
		}
		s.mu.Unlock()
		return 0, err
	}
	n, _ := s.data.Read(p)
	s.mu.Unlock()
	if err := s.credit(n); err != nil {
		s.fail(err)
	}
	return n, nil
}

func (s *h2Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.mu.Lock()
		for s.err == nil && (s.sendConn <= 0 || s.sendStream <= 0) {
			s.cond.Wait()
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return written, err
		}
		n := min(len(p), s.maxFrame, int(s.sendConn), int(s.sendStream))
		s.sendConn -= int64(n)
		s.sendStream -= int64(n)
		id := s.id
		s.mu.Unlock()
		if err := s.frame(func() error { return s.framer.WriteData(id, false, p[:n]) }); err != nil {
			s.fail(err)
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (s *h2Stream) writeHeaders(fields []hpack.HeaderField) error {
	var b bytes.Buffer
	encoder := hpack.NewEncoder(&b)
	// Each header block is independent, with no dynamic table references.
	encoder.SetMaxDynamicTableSize(0)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	if b.Len() > 16384 {
		return errors.New("masque: CONNECT headers too large")
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	return s.frame(func() error {
		return s.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: b.Bytes(), EndHeaders: true})
	})
}

func (s *h2Stream) waitHeaders(ctx context.Context) (*http2.MetaHeadersFrame, error) {
	select {
	case h := <-s.headers:
		return h, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		// Preserve a final response even when the peer immediately closes.
		select {
		case h := <-s.headers:
			return h, nil
		default:
		}
		s.mu.Lock()
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
}

func dialHTTP2(ctx context.Context, remote string, config *tls.Config, request *http.Request, allowMissing ...bool) (io.ReadWriteCloser, error) {
	config = config.Clone()
	config.NextProtos = []string{"h2"}
	conn, err := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("%w: peer did not negotiate HTTP/2", ErrHTTPVersionUnavailable)
	}
	s, err := newH2Stream(conn, false)
	if err != nil {
		return nil, err
	}
	select {
	case <-s.settings:
	case <-s.done:
		s.mu.Lock()
		err := s.err
		s.mu.Unlock()
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.mu.Lock()
	extended := s.extended
	s.mu.Unlock()
	if !extended && !(len(allowMissing) > 0 && allowMissing[0]) {
		return nil, fmt.Errorf("%w: peer does not enable HTTP/2 extended CONNECT", ErrHTTPVersionUnavailable)
	}
	fields := []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":protocol", Value: connectProtocol(request)},
		{Name: ":scheme", Value: "https"}, {Name: ":authority", Value: request.Host}, {Name: ":path", Value: request.URL.RequestURI()}}
	for name, values := range request.Header {
		for _, value := range values {
			fields = append(fields, hpack.HeaderField{Name: strings.ToLower(name), Value: value, Sensitive: strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization")})
		}
	}
	if err := s.writeHeaders(fields); err != nil {
		return nil, err
	}
	headers, err := s.waitHeaders(ctx)
	if err != nil {
		return nil, err
	}
	status, _ := strconv.Atoi(headers.PseudoValue("status"))
	if status < 200 || status > 299 {
		return nil, fmt.Errorf("masque: HTTP/2 CONNECT rejected: %d", status)
	}
	if !stop() {
		return nil, ctx.Err()
	}
	success = true
	return s, nil
}

// h2Response keeps the handler alive for the full duplex CONNECT stream.
type h2Response struct {
	stream *h2Stream
	header http.Header
	sent   bool
	err    error
}

func (w *h2Response) Header() http.Header { return w.header }
func (w *h2Response) WriteHeader(status int) {
	if w.sent {
		return
	}
	w.sent = true
	fields := []hpack.HeaderField{{Name: ":status", Value: strconv.Itoa(status)}}
	for name, values := range w.header {
		for _, value := range values {
			fields = append(fields, hpack.HeaderField{Name: strings.ToLower(name), Value: value})
		}
	}
	w.err = w.stream.writeHeaders(fields)
}
func (w *h2Response) Write(p []byte) (int, error) {
	if !w.sent {
		w.WriteHeader(200)
	}
	if w.err != nil {
		return 0, w.err
	}
	return w.stream.Write(p)
}
func (w *h2Response) FlushError() error {
	if !w.sent {
		w.WriteHeader(200)
	}
	return w.err
}

func serveHTTP2(ctx context.Context, conn *tls.Conn, handler http.Handler) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	handshakeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	s, err := newH2Stream(conn, true)
	if err != nil {
		return
	}
	defer s.Close()
	headers, err := s.waitHeaders(handshakeCtx)
	if err != nil {
		return
	}
	u, err := url.ParseRequestURI(headers.PseudoValue("path"))
	if err != nil || headers.PseudoValue("scheme") != "https" || headers.PseudoValue("authority") == "" {
		return
	}
	request := &http.Request{Method: headers.PseudoValue("method"), Proto: headers.PseudoValue("protocol"), ProtoMajor: 2,
		URL: u, Host: headers.PseudoValue("authority"), Header: make(http.Header), Body: s, RemoteAddr: conn.RemoteAddr().String()}
	for _, field := range headers.RegularFields() {
		request.Header.Add(field.Name, field.Value)
	}
	_ = conn.SetDeadline(time.Time{})
	handler.ServeHTTP(&h2Response{stream: s, header: make(http.Header)}, request.WithContext(ctx))
}
