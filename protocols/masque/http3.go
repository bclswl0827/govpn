package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// ErrDatagramsUnavailable permits capsule fallback when datagrams cannot be sent.
var ErrDatagramsUnavailable = errors.New("masque: peer did not negotiate HTTP datagrams")
var errDatagramsUnavailable = ErrDatagramsUnavailable

// ErrDatagramTooLarge lets custom transports request capsule fallback for one packet.
var ErrDatagramTooLarge = errors.New("masque: datagram exceeds transport limit")

type datagramTransport interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type quicStream interface {
	io.ReadWriteCloser
	datagramTransport
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

type h3Stream struct {
	quicStream
	datagramOverhead int64
	datagrams        bool
	closeConnection  func() error
	once             sync.Once
}

func (s *h3Stream) Close() error {
	s.once.Do(func() {
		s.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = s.quicStream.Close()
		if s.closeConnection != nil {
			_ = s.closeConnection()
		}
	})
	return nil
}
func (s *h3Stream) SendDatagram(p []byte) error {
	if !s.datagrams {
		return errDatagramsUnavailable
	}
	err := s.quicStream.SendDatagram(p)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		// quic-go reports the QUIC payload limit, including the HTTP/3
		// quarter-stream ID. Expose only the adapter payload capacity.
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: tooLarge.MaxDatagramPayloadSize - s.datagramOverhead}
	}
	return err
}
func (s *h3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if !s.datagrams {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.quicStream.ReceiveDatagram(ctx)
}

func quicConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second, MaxIdleTimeout: 45 * time.Second}
}

func dialHTTP3(ctx context.Context, remote string, config *tls.Config, request *http.Request) (io.ReadWriteCloser, error) {
	return dialHTTP3Options(ctx, remote, config, request, HTTP3Options{}, false)
}

func dialHTTP3Options(ctx context.Context, remote string, config *tls.Config, request *http.Request, options HTTP3Options, allowMissing bool) (io.ReadWriteCloser, error) {
	config = config.Clone()
	config.NextProtos = []string{http3.NextProtoH3}
	conn, closeQUIC, err := dialQUIC(ctx, remote, config, options)
	if err != nil {
		return nil, err
	}
	transport := &http3.Transport{EnableDatagrams: true, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, AdditionalSettings: options.AdditionalSettings}
	cleanup := func() error {
		_ = conn.CloseWithError(0, "")
		_ = transport.Close()
		return closeQUIC()
	}
	success := false
	defer func() {
		if !success {
			_ = cleanup()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = cleanup() })
	defer stop()
	client := transport.NewClientConn(conn)
	select {
	case <-client.ReceivedSettings():
	case <-conn.Context().Done():
		return nil, context.Cause(conn.Context())
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if !client.Settings().EnableExtendedConnect && !allowMissing {
		return nil, fmt.Errorf("%w: peer does not enable HTTP/3 extended CONNECT", ErrHTTPVersionUnavailable)
	}
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	request.Method, request.Proto = http.MethodConnect, connectProtocol(request)
	request.URL.Scheme = "https"
	if request.URL.Host == "" {
		request.URL.Host = request.Host
	}
	if err := stream.SendRequestHeader(request); err != nil {
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("masque: HTTP/3 CONNECT rejected: %s", response.Status)
	}
	if !stop() {
		return nil, ctx.Err()
	}
	success = true
	return &h3Stream{quicStream: stream, datagramOverhead: int64(quicvarint.Len(uint64(stream.StreamID() / 4))), datagrams: client.Settings().EnableDatagrams && conn.ConnectionState().SupportsDatagrams.Remote, closeConnection: cleanup}, nil
}

// Keep the original DialAddr path for standard clients. A custom CID length
// requires owning the UDP socket and QUIC transport explicitly.
func dialQUIC(ctx context.Context, remote string, config *tls.Config, options HTTP3Options) (*quic.Conn, func() error, error) {
	qconfig := quicConfigFor(options, DefaultMTU)
	if options.ConnectionIDLength == 0 {
		conn, err := quic.DialAddr(ctx, remote, config, qconfig)
		return conn, func() error { return nil }, err
	}
	host, portText, err := net.SplitHostPort(remote)
	if err != nil {
		return nil, nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("masque: endpoint resolved to no addresses")
	}
	ip := ips[0].Unmap()
	network, local := "udp4", "0.0.0.0:0"
	if ip.Is6() {
		network, local = "udp6", "[::]:0"
	}
	socket, err := net.ListenPacket(network, local)
	if err != nil {
		return nil, nil, err
	}
	qt := &quic.Transport{Conn: socket, ConnectionIDLength: options.ConnectionIDLength}
	cleanup := func() error { _ = qt.Close(); return socket.Close() }
	conn, err := qt.Dial(ctx, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: port, Zone: ip.Zone()}, config, qconfig)
	if err != nil {
		_ = cleanup()
		return nil, nil, err
	}
	return conn, cleanup, nil
}

func acceptHTTP3(ctx context.Context, w http.ResponseWriter) (io.ReadWriteCloser, error) {
	settings, ok := w.(http3.Settingser)
	if !ok {
		return nil, errors.New("masque: HTTP/3 settings unavailable")
	}
	select {
	case <-settings.ReceivedSettings():
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("masque: HTTP/3 stream unavailable")
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return nil, err
	}
	stream := streamer.HTTPStream()
	return &h3Stream{quicStream: stream, datagramOverhead: int64(quicvarint.Len(uint64(stream.StreamID() / 4))), datagrams: settings.Settings().EnableDatagrams}, nil
}

func quicConfigFor(options HTTP3Options, mtu int) *quic.Config {
	config := quicConfig()
	if options.QUICConfig != nil {
		config = options.QUICConfig.Clone()
	}
	config.EnableDatagrams = true
	if config.InitialPacketSize == 0 {
		config.InitialPacketSize = uint16(min(mtu+51, 65535))
	}
	return config
}
