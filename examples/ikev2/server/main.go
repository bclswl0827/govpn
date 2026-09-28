package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/ikev2"
)

func main() {
	listen := flag.String("listen", "127.0.0.1", "outer UDP listen IPv4 address")
	public := flag.String("public", "", "public IPv4 address used for NAT detection")
	serverID := flag.String("server-id", "vpn.example", "IKEv2 responder identity")
	clientID := flag.String("client-id", "alice", "accepted IKEv2 initiator identity")
	psk := flag.String("psk", "", "IKEv2 pre-shared key")
	username := flag.String("username", "", "accepted EAP-MSCHAPv2 username")
	password := flag.String("password", "", "EAP-MSCHAPv2 password")
	certFile := flag.String("cert", "", "PEM responder certificate chain for password authentication")
	keyFile := flag.String("key", "", "PEM RSA responder private key for password authentication")
	allowLegacyMODP1024 := flag.Bool("allow-legacy-modp1024", false, "accept obsolete MODP-1024 initiators")
	flag.Parse()
	users := make(map[string]string)
	if *psk != "" {
		users[*clientID] = *psk
	}
	passwordUsers := make(map[string]string)
	if *username != "" || *password != "" {
		passwordUsers[*username] = *password
	}
	var certificate, privateKey []byte
	var err error
	if *certFile != "" {
		certificate, err = os.ReadFile(*certFile)
		exampleutil.Must(err)
	}
	if *keyFile != "" {
		privateKey, err = os.ReadFile(*keyFile)
		exampleutil.Must(err)
	}

	server, err := ikev2.NewServer(ikev2.ServerConfig{
		ListenIP:            *listen,
		PublicIP:            *public,
		Identity:            *serverID,
		Users:               users,
		PasswordUsers:       passwordUsers,
		Certificate:         certificate,
		PrivateKey:          privateKey,
		AllowLegacyMODP1024: *allowLegacyMODP1024,
		Pool:                exampleutil.InternalCIDR,
	})
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := server.Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeServer(ctx, session))
}
