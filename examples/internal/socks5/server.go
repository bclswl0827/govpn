package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func Serve(ctx context.Context, listener net.Listener, dialer Dialer, logger *log.Logger) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept SOCKS5 connection: %w", err)
		}
		remote := fmt.Sprint(conn.RemoteAddr())
		logf(logger, "accepted client: remote=%s", remote)
		go func(conn net.Conn, remote string) {
			defer conn.Close()
			if err := handle(ctx, conn, dialer, logger); err != nil {
				logf(logger, "client ended with error: remote=%s error=%v", remote, err)
			} else {
				logf(logger, "client closed: remote=%s", remote)
			}
		}(conn, remote)
	}
}

func handle(ctx context.Context, client net.Conn, dialer Dialer, logger *log.Logger) error {
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	if err := negotiate(client); err != nil {
		return err
	}
	command, network, address, err := readRequest(client)
	if err != nil {
		_ = writeReply(client, addressError, nil)
		return err
	}
	if command != connectCommand {
		_ = writeReply(client, commandError, nil)
		return errors.New("SOCKS5 command is not supported")
	}

	logf(logger, "connecting: remote=%s network=%s target=%s", client.RemoteAddr(), network, address)
	dialContext, cancelDial := context.WithTimeout(ctx, 30*time.Second)
	defer cancelDial()
	upstream, err := dialer.DialContext(dialContext, network, address)
	if err != nil {
		_ = writeReply(client, generalError, nil)
		return fmt.Errorf("SOCKS5 connect: %w", err)
	}
	defer upstream.Close()
	logf(logger, "connected: remote=%s target=%s", client.RemoteAddr(), address)
	if err := writeReply(client, succeeded, upstream.LocalAddr()); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})

	var wait sync.WaitGroup
	wait.Add(2)
	copyStream := func(destination, source net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(destination, source)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	wait.Wait()
	return nil
}

func logf(logger *log.Logger, format string, arguments ...any) {
	if logger != nil {
		logger.Printf("[socks5] "+format, arguments...)
	}
}
