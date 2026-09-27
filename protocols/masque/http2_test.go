package masque

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func h2Pair(t *testing.T) (*h2Stream, *h2Stream) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type result struct {
		stream *h2Stream
		err    error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		stream, err := newH2Stream(conn, true)
		if err != nil {
			_ = conn.Close()
		}
		accepted <- result{stream, err}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	client, err := newH2Stream(conn, false)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.stream.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.writeHeaders([]hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"}, {Name: ":protocol", Value: "connect-ip"},
		{Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: DefaultPath},
	}); err != nil {
		t.Fatal(err)
	}
	request, err := server.stream.waitHeaders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if request.PseudoValue("protocol") != "connect-ip" {
		t.Fatal("missing extended CONNECT protocol")
	}
	if err := server.stream.writeHeaders([]hpack.HeaderField{{Name: ":status", Value: "200"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.waitHeaders(ctx); err != nil {
		t.Fatal(err)
	}
	return client, server.stream
}

func TestHTTP2FlowControl(t *testing.T) {
	client, server := h2Pair(t)
	payload := bytes.Repeat([]byte("flow-control"), 32768) // Several initial windows.
	results := make(chan error, 4)
	for _, pair := range [][2]*h2Stream{{client, server}, {server, client}} {
		go func() { _, err := pair[0].Write(payload); results <- err }()
		go func() {
			got := make([]byte, len(payload))
			_, err := io.ReadFull(pair[1], got)
			if err == nil && !bytes.Equal(got, payload) {
				err = io.ErrUnexpectedEOF
			}
			results <- err
		}()
	}
	for range 4 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTP2CloseUnblocksFlowControl(t *testing.T) {
	client, _ := h2Pair(t)
	client.mu.Lock()
	client.sendStream = 0
	client.mu.Unlock()
	result := make(chan error, 1)
	go func() { _, err := client.Write([]byte("blocked")); result <- err }()
	_ = client.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("write succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("flow-control wait did not unblock")
	}
}
