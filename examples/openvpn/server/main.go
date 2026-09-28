package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/openvpn"
)

func main() {
	caPath := flag.String("ca", "ca.crt", "client CA certificate PEM")
	certPath := flag.String("cert", "server.crt", "server certificate PEM")
	keyPath := flag.String("key", "server.key", "server private key PEM")
	listen := flag.String("listen", "127.0.0.1", "outer UDP listen IP")
	port := flag.Int("port", 1194, "outer UDP listen port")
	flag.Parse()

	ca, err := os.ReadFile(*caPath)
	exampleutil.Must(err)
	cert, err := os.ReadFile(*certPath)
	exampleutil.Must(err)
	key, err := os.ReadFile(*keyPath)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := openvpn.NewServer(openvpn.ServerConfig{
		CA: ca, Cert: cert, Key: key, ListenIP: *listen, ListenPort: *port, Pool: exampleutil.InternalCIDR,
		TrafficPolicy: exampleutil.ExampleTrafficPolicy(), OnTrafficDecision: exampleutil.LogTrafficDecision,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeServer(ctx, session))
}
