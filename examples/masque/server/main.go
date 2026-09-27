package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/masque"
)

func main() {
	versionList := flag.String("versions", "1,2,3", "comma-separated HTTP versions to serve")
	certPath := flag.String("cert", "server.crt", "server TLS certificate PEM")
	keyPath := flag.String("key", "server.key", "server TLS private key PEM")
	listen := flag.String("listen", "127.0.0.1", "outer TCP/UDP listen IP")
	port := flag.Int("port", 4443, "outer TCP/UDP listen port")
	username := flag.String("username", "alice", "HTTP Basic username")
	password := flag.String("password", "change-me", "HTTP Basic password")
	path := flag.String("path", masque.DefaultTemplate, "CONNECT-IP path or URI template")
	pool := flag.String("pool", exampleutil.InternalCIDR, "IPv4 client address pool")
	ipv6Pool := flag.String("ipv6-pool", "", "optional IPv6 client address pool")
	var routes []netip.Prefix
	flag.Func("advertise-route", "permitted destination CIDR; repeatable (empty permits all)", func(value string) error {
		prefix, err := netip.ParsePrefix(value)
		if err == nil {
			routes = append(routes, prefix)
		}
		return err
	})
	flag.Parse()

	var versions []int
	for _, value := range strings.Split(*versionList, ",") {
		version, err := strconv.Atoi(strings.TrimSpace(value))
		exampleutil.Must(err)
		if version < 1 || version > 3 {
			exampleutil.Must(fmt.Errorf("invalid HTTP version %d", version))
		}
		versions = append(versions, version)
	}
	cert, err := os.ReadFile(*certPath)
	exampleutil.Must(err)
	key, err := os.ReadFile(*keyPath)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := masque.NewServer(masque.ServerConfig{
		Versions: versions, Cert: cert, Key: key, ListenIP: *listen, ListenPort: *port,
		Path: *path, Pool: *pool, IPv6Pool: *ipv6Pool, AdvertiseRoutes: routes, Users: map[string]string{*username: *password},
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeServer(ctx, session))
}
