package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"bufio"
	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// This independent HTTP/2 peer deliberately omits ENABLE_CONNECT_PROTOCOL.
// It also requires a client certificate, exercising the TLS extension end to end.
func TestHTTP2PrivateProtocolRequiresExplicitOptIn(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	for _, allow := range []bool{false, true} {
		t.Run(strconv.FormatBool(allow), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, ClientAuth: tls.RequireAnyClientCert})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			observed := make(chan []hpack.HeaderField, 1)
			finished := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					finished <- err
					return
				}
				if string(preface) != http2.ClientPreface {
					finished <- errors.New("bad preface")
					return
				}
				framer := http2.NewFramer(conn, conn)
				framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				if err := framer.WriteSettings(); err != nil {
					finished <- err
					return
				}
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						finished <- err
						return
					}
					switch f := frame.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							if err := framer.WriteSettingsAck(); err != nil {
								finished <- err
								return
							}
						}
					case *http2.MetaHeadersFrame:
						observed <- append([]hpack.HeaderField(nil), f.Fields...)
						var block bytes.Buffer
						encoder := hpack.NewEncoder(&block)
						if err := encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
							finished <- err
							return
						}
						if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
							finished <- err
							return
						}
						<-ctx.Done()
						finished <- nil
						return
					}
				}
			}()
			host, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			c := Config{Server: host, Port: port, Version: 2, ConnectURL: "https://private.example/tunnel?q=1", Protocol: "vendor-ip",
				AllowMissingExtendedConnect: allow, Headers: http.Header{"X-Vendor": {"yes"}},
				TLSConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}},
			}
			d, _, _, err := prepareClient(c)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := (DefaultTunnelDialer{}).DialTunnel(ctx, d)
			if !allow {
				if err == nil {
					stream.Close()
					t.Fatal("missing setting accepted by default")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				fields := <-observed
				values := map[string]string{}
				for _, f := range fields {
					values[f.Name] = f.Value
				}
				if values[":protocol"] != "vendor-ip" || values[":authority"] != "private.example" || values[":path"] != "/tunnel?q=1" || values["x-vendor"] != "yes" {
					t.Fatalf("wire headers: %v", values)
				}
			}
			cancel()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("peer failed to stop")
			}
		})
	}
}

func TestHTTP3CustomRequestSettingsAndTLSVerification(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certificateServer.TLS.Certificates[0]
	leaf := certificateServer.Certificate()
	certificateServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	observed := make(chan error, 1)
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, EnableDatagrams: true}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "vendor-ip" || r.Host != "private.example" || r.URL.RequestURI() != "/private" || r.Header.Get("X-Vendor") != "yes" {
			observed <- errors.New("incorrect HTTP/3 request")
			w.WriteHeader(400)
			return
		}
		settings := w.(http3.Settingser)
		select {
		case <-settings.ReceivedSettings():
		case <-ctx.Done():
			observed <- ctx.Err()
			return
		}
		if settings.Settings().Other[0x276] != 1 {
			observed <- errors.New("missing extra setting")
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		if err := http.NewResponseController(w).Flush(); err != nil {
			observed <- err
			return
		}
		observed <- nil
		stream := w.(http3.HTTPStreamer).HTTPStream()
		defer stream.Close()
		io.Copy(stream, stream)
	})
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(socket) }()
	defer func() { server.Close(); <-finished }()
	host, portText, _ := net.SplitHostPort(socket.LocalAddr().String())
	port, _ := strconv.Atoi(portText)
	verifyErr := errors.New("pin mismatch")
	for _, reject := range []bool{true, false} {
		c := Config{Server: host, Port: port, Version: 3, ConnectURL: "https://private.example/private", Protocol: "vendor-ip",
			Headers: http.Header{"X-Vendor": {"yes"}}, HTTP3: HTTP3Options{ConnectionIDLength: 20, AdditionalSettings: map[uint64]uint64{0x276: 1}},
			TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "custom-sni.example", VerifyConnection: func(state tls.ConnectionState) error {
				if reject {
					return verifyErr
				}
				if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
					return verifyErr
				}
				return nil
			}},
		}
		d, _, _, err := prepareClient(c)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := (DefaultTunnelDialer{}).DialTunnel(ctx, d)
		if reject {
			if err == nil {
				stream.Close()
				t.Fatal("TLS verification callback bypassed")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
		defer stop()
		if err := <-observed; err != nil {
			stream.Close()
			t.Fatal(err)
		}
		data := []byte{99, 3, 1, 2, 3}
		if _, err := stream.Write(data); err != nil {
			stream.Close()
			t.Fatal(err)
		}
		got := make([]byte, len(data))
		if _, err := io.ReadFull(stream, got); err != nil {
			stream.Close()
			t.Fatal(err)
		}
		stream.Close()
		if !bytes.Equal(got, data) {
			t.Fatal("capsule stream corrupted")
		}
	}
}

// A raw QUIC peer advertises no Extended CONNECT support. This covers the
// compatibility path independently of http3.Server, which always advertises it.
func TestHTTP3MissingExtendedConnectSetting(t *testing.T) {
	certificates := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certificates.TLS.Certificates[0]
	certificates.Close()
	for _, allow := range []bool{false, true} {
		t.Run(strconv.FormatBool(allow), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, quicConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			finished := make(chan error, 1)
			go func() {
				conn, err := listener.Accept(ctx)
				if err != nil {
					finished <- err
					return
				}
				defer conn.CloseWithError(0, "")
				stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "") })
				defer stop()
				control, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					finished <- err
					return
				}
				// Control stream type 0, SETTINGS frame type 4, empty payload.
				if _, err := control.Write([]byte{0, 4, 0}); err != nil {
					finished <- err
					return
				}
				request, err := conn.AcceptStream(ctx)
				if err != nil {
					finished <- err
					return
				}
				reader := bufio.NewReader(request)
				kind, err := readVarint(reader)
				if err != nil || kind != 1 {
					finished <- errors.New("missing request HEADERS")
					return
				}
				size, err := readVarint(reader)
				if err != nil || size > 16384 {
					finished <- errors.New("invalid request HEADERS length")
					return
				}
				block := make([]byte, int(size))
				if _, err := io.ReadFull(reader, block); err != nil {
					finished <- err
					return
				}
				decode := qpack.NewDecoder().Decode(block)
				found := false
				for {
					field, err := decode()
					if err == io.EOF {
						break
					}
					if err != nil {
						finished <- err
						return
					}
					if field.Name == ":protocol" && field.Value == "vendor-ip" {
						found = true
					}
				}
				if !found {
					finished <- errors.New("private protocol missing")
					return
				}
				var response bytes.Buffer
				encoder := qpack.NewEncoder(&response)
				if err := encoder.WriteField(qpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
					finished <- err
					return
				}
				header := appendVarint([]byte{1}, uint64(response.Len()))
				if _, err := request.Write(append(header, response.Bytes()...)); err != nil {
					finished <- err
					return
				}
				<-ctx.Done()
				finished <- nil
			}()
			host, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			d, _, _, err := prepareClient(Config{Server: host, Port: port, Version: 3, Protocol: "vendor-ip", SkipVerify: true, AllowMissingExtendedConnect: allow})
			if err != nil {
				t.Fatal(err)
			}
			stream, err := (DefaultTunnelDialer{}).DialTunnel(ctx, d)
			if allow && err != nil {
				t.Fatal(err)
			}
			if !allow && err == nil {
				stream.Close()
				t.Fatal("missing setting accepted without opt-in")
			}
			if stream != nil {
				stream.Close()
			}
			cancel()
			select {
			case err := <-finished:
				if allow && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("raw HTTP/3 peer failed to stop")
			}
		})
	}
}
