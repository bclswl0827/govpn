package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/l2tp"
)

func main() {
	listen := flag.String("listen", "127.0.0.1", "outer UDP listen IP")
	public := flag.String("public", "", "public IPv4 address clients use")
	psk := flag.String("psk", "", "IPsec pre-shared key")
	username := flag.String("username", "alice", "PPP MS-CHAPv2 username")
	password := flag.String("password", "change-me", "PPP MS-CHAPv2 password")
	flag.Parse()

	server, err := l2tp.NewServer(l2tp.ServerConfig{
		ListenIP:          *listen,
		PublicIP:          *public,
		PSK:               *psk,
		Users:             map[string]string{*username: *password},
		Pool:              exampleutil.InternalCIDR,
		TrafficPolicy:     exampleutil.ExampleTrafficPolicy(),
		OnTrafficDecision: exampleutil.LogTrafficDecision,
	})
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := server.Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeServer(ctx, session))
}
