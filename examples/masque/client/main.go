package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/masque"
)

func main() {
	version := flag.Int("version", 3, "preferred HTTP version: 1, 2, or 3")
	server := flag.String("server", "127.0.0.1", "MASQUE server hostname")
	port := flag.Int("port", 4443, "MASQUE server port")
	username := flag.String("username", "alice", "HTTP Basic username")
	password := flag.String("password", "change-me", "HTTP Basic password")
	insecure := flag.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	caPath := flag.String("ca", "", "trusted server CA PEM file")
	serverName := flag.String("server-name", "", "TLS server name override")
	path := flag.String("path", masque.DefaultTemplate, "CONNECT-IP path or URI template")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	disableFallback := flag.Bool("disable-version-fallback", false, "disable fallback to lower HTTP versions")
	disableReconnect := flag.Bool("disable-reconnect", false, "end the session when its connection fails")
	onDemand := flag.Bool("on-demand", false, "wait for tunnel readiness when opening connections")
	target := flag.String("target", "", "URI-template target IP, prefix, or hostname")
	ipProtocol := flag.Uint("ipproto", 0, "URI-template IP protocol number; 0 means all")
	var routes []netip.Prefix
	flag.Func("advertise-route", "client-side routed CIDR; repeatable", func(value string) error {
		prefix, err := netip.ParsePrefix(value)
		if err == nil {
			routes = append(routes, prefix)
		}
		return err
	})
	flag.Parse()
	if *ipProtocol > 255 {
		exampleutil.Must(fmt.Errorf("-ipproto must be between 0 and 255"))
	}

	var ca []byte
	if *caPath != "" {
		var err error
		ca, err = os.ReadFile(*caPath)
		exampleutil.Must(err)
	}
	ctx := exampleutil.Context()
	client := masque.NewClient(masque.Config{
		Server: *server, Port: *port, Username: *username, Password: *password, SkipVerify: *insecure,
		Version: *version, CA: ca, ServerName: *serverName, Path: *path,
		DisableVersionFallback: *disableFallback, DisableReconnect: *disableReconnect, OnDemand: *onDemand,
		Target: *target, IPProtocol: uint8(*ipProtocol), AdvertiseRoutes: routes,
	})
	session, err := client.Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, client))
}
