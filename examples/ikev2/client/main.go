package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/ikev2"
)

func main() {
	server := flag.String("server", "", "IKEv2 server hostname or IPv4 address")
	clientID := flag.String("client-id", "alice", "IKEv2 initiator identity")
	serverID := flag.String("server-id", "vpn.example", "required IKEv2 responder identity")
	psk := flag.String("psk", "", "IKEv2 pre-shared key")
	username := flag.String("username", "", "EAP-MSCHAPv2 username (mutually exclusive with -psk)")
	password := flag.String("password", "", "EAP-MSCHAPv2 password")
	caFile := flag.String("ca", "", "PEM CA certificate used to verify the responder")
	serverName := flag.String("server-name", "", "responder certificate DNS name or IP (defaults to -server-id)")
	skipVerify := flag.Bool("insecure-skip-verify", false, "skip responder certificate chain and name verification")
	allowLegacyMODP1024 := flag.Bool("allow-legacy-modp1024", false, "use obsolete MODP-1024 for legacy servers")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	flag.Parse()
	var ca []byte
	var err error
	if *caFile != "" {
		ca, err = os.ReadFile(*caFile)
		exampleutil.Must(err)
	}

	ctx := exampleutil.Context()
	session, err := ikev2.NewClient(ikev2.Config{
		Server: *server, LocalID: *clientID, RemoteID: *serverID, PSK: *psk,
		Username: *username, Password: *password, CA: ca, ServerName: *serverName,
		SkipVerify: *skipVerify, AllowLegacyMODP1024: *allowLegacyMODP1024,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, session))
}
