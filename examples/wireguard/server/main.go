package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/wireguard"
)

func main() {
	privateKey := flag.String("private-key", "", "server WireGuard private key")
	peerPublicKey := flag.String("peer-public-key", "", "client WireGuard public key")
	listen := flag.String("listen", "0.0.0.0", "outer UDP listen IP")
	port := flag.Int("port", 51820, "outer UDP listen port")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := wireguard.NewServer(wireguard.ServerConfig{
		PrivateKey:        *privateKey,
		ListenIP:          *listen,
		ListenPort:        *port,
		Address:           exampleutil.ServerPrefix,
		TrafficPolicy:     exampleutil.ExampleTrafficPolicy(),
		OnTrafficDecision: exampleutil.LogTrafficDecision,
		Peers: []wireguard.ServerPeer{{
			PublicKey:  *peerPublicKey,
			AllowedIPs: []string{"192.168.168.2/32"},
		}},
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeServer(ctx, session))
}
