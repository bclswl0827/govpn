package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	sshvpn "github.com/bclswl0827/govpn/protocols/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func main() {
	hostKeyPath := flag.String("host-key", "./host_key", "SSH host key; generated when missing")
	listenIP := flag.String("listen", "::", "SSH listen IP")
	port := flag.Int("port", 2222, "SSH listen port")
	username := flag.String("username", "root", "SSH login username")
	password := flag.String("password", "passw0rd", "SSH login password")
	shell := flag.String("shell", "/bin/sh", "shell for PTY sessions on Unix")
	mtu := flag.Int("mtu", 1500, "userspace tunnel MTU")
	flag.Parse()

	hostKey, err := loadOrCreateHostKey(*hostKeyPath)
	exampleutil.Must(err)
	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	server := sshvpn.NewServer(sshvpn.ServerConfig{
		HostKey: hostKey,
		Users: map[string]sshvpn.ServerUser{
			*username: {Password: *password},
		},
		Address:           []string{exampleutil.ServerPrefix},
		MTU:               *mtu,
		Timeout:           15 * time.Second,
		KeepaliveInterval: 30 * time.Second,
		Logger:            logger,
		TrafficPolicy:     exampleutil.ExampleTrafficPolicy(),
		OnTrafficDecision: exampleutil.LogTrafficDecision,
	})
	exampleutil.Must(registerSessionHandlers(server, *shell, logger))
	exampleutil.Must(server.RegisterSessionRequestHandler("subsystem", sftpHandler(logger)))

	ctx := exampleutil.Context()
	listenAddress := net.JoinHostPort(strings.TrimSpace(*listenIP), fmt.Sprint(*port))
	listener, err := net.Listen("tcp", listenAddress)
	exampleutil.Must(err)
	defer listener.Close()
	logger.Printf("SSH server listening on %s", listener.Addr())
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		rawConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("accept SSH connection: %v", acceptErr)
			continue
		}
		go serveConnection(ctx, server, rawConnection, logger)
	}
}

func serveConnection(ctx context.Context, server *sshvpn.Server, rawConnection net.Conn, logger *log.Logger) {
	remoteAddress := rawConnection.RemoteAddr()
	err := server.HandleConn(ctx, rawConnection, func(tunnelCtx context.Context, connection *gossh.ServerConn, session *govpn.Session) {
		logger.Printf("tunnel started: user=%s remote=%s addresses=%v", connection.User(), connection.RemoteAddr(), session.Addresses())
		if serviceErr := exampleutil.ServeServer(tunnelCtx, session); serviceErr != nil {
			logger.Printf("tunnel services ended: user=%s error=%v", connection.User(), serviceErr)
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("SSH connection ended: remote=%s error=%v", remoteAddress, err)
		return
	}
	logger.Printf("SSH connection closed: remote=%s", remoteAddress)
}
