package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/softether"
)

func main() {
	certPath := flag.String("cert", "server.crt", "server TLS certificate PEM")
	keyPath := flag.String("key", "server.key", "server TLS private key PEM")
	listen := flag.String("listen", "127.0.0.1", "outer TCP listen IP")
	port := flag.Int("port", 4443, "outer TCP listen port")
	hub := flag.String("hub", "DEFAULT", "virtual hub name")
	username := flag.String("username", "alice", "SoftEther username")
	password := flag.String("password", "change-me", "SoftEther password")
	flag.Parse()

	cert, err := os.ReadFile(*certPath)
	exampleutil.Must(err)
	key, err := os.ReadFile(*keyPath)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := softether.NewServer(softether.ServerConfig{
		Cert: cert, Key: key, ListenIP: *listen, ListenPort: *port,
		Hub: *hub, Pool: exampleutil.InternalCIDR, Users: map[string]string{*username: *password},
		TrafficPolicy: exampleutil.ExampleTrafficPolicy(), OnTrafficDecision: exampleutil.LogTrafficDecision,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeServer(ctx, session))
}
