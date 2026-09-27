package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

type bufferedStream struct {
	io.ReadWriteCloser
	reader *bufio.Reader
}

func (s *bufferedStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

func dialHTTP1(ctx context.Context, remote string, config *tls.Config, request *http.Request) (io.ReadWriteCloser, error) {
	config = config.Clone()
	config.NextProtos = []string{"http/1.1"}
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
	request.Method = http.MethodGet
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "connect-ip")
	if err := request.Write(conn); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: conn, N: 16 << 10}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols || !upgradeHeader(response.Header) {
		_ = response.Body.Close()
		return nil, fmt.Errorf("masque: CONNECT-IP Upgrade rejected: %s", response.Status)
	}
	limited.N = 1<<63 - 1
	if !stop() {
		return nil, ctx.Err()
	}
	success = true
	return &bufferedStream{ReadWriteCloser: conn, reader: reader}, nil
}
