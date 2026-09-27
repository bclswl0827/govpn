# MASQUE examples

These examples support TLS HTTP/1.1 Upgrade, HTTP/2 Extended CONNECT, and
HTTP/3 CONNECT-IP. HTTP/3 uses QUIC datagrams where negotiated and falls back
to capsules when datagrams are unavailable. Oversized QUIC datagrams produce
ICMP Packet Too Big; a path unable to carry 1280-byte IP packets ends the tunnel.
HTTP/1.1 and HTTP/2 carry IP packets in capsules. No root privileges, TUN device,
or host route changes are required. Multiple clients can connect concurrently
across all enabled versions, with distinct allocated addresses.

## Examples

Create a local development certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout server.key -out server.crt -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
```

Start the server and client in separate terminals from the repository root:

```sh
go run ./examples/masque/server -cert server.crt -key server.key \
  -listen 127.0.0.1 -port 4443 -versions 1,2,3 -username alice -password change-me
```

```sh
go run ./examples/masque/client -server 127.0.0.1 -port 4443 \
  -version 3 -ca server.crt -username alice -password change-me -socks5 127.0.0.1:1080
```

Select `-version 2` to prefer HTTP/2 or `-version 1` for HTTP/1.1. Transport
unavailability allows fallback to lower versions; use `-disable-version-fallback`
to require the selected version. HTTP rejection and TLS verification failures
never cause fallback. The server
uses TCP port 4443 for HTTP/1.1 and HTTP/2, and UDP port 4443 for HTTP/3.
Use `-versions 2` or `-versions 3` to enable only that transport.

The server uses `192.168.168.1`; the first client receives `192.168.168.2/32`.
Subsequent clients receive distinct addresses from the pool.
The server exposes HTTP on port 80 and an egress SOCKS5 service on port 1080
inside the VPN. The local client proxy chooses the appropriate service:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://192.168.168.1/
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

The first request should return `VPN works!`. The second uses the server's
host network via its explicit egress proxy; the VPN server does not perform NAT.

## Configuration

Use `masque.NewClient(masque.Config{...}).Start(ctx)` and
`masque.NewServer(masque.ServerConfig{...}).Start(ctx)` like the other protocols.
`ServerConfig.Pool` configures IPv4; `IPv6Pool` optionally configures IPv6,
for example `fd00:168::/64`. Either or both can be supplied. `MTU` defaults to
1280 on both sides and should match. Certificates and CA are PEM bytes.
Empty `ServerConfig.Users` disables authentication. `Config.Version` selects
1, 2, or 3; zero defaults to HTTP/3. `ServerConfig.Versions` defaults to `[]int{1, 2, 3}`. Each HTTP/2
connection carries one CONNECT stream; HTTP/2 flow control is handled internally.

`ServerConfig.Address` alternatively accepts explicit server host addresses and
allocation prefixes, such as `192.168.168.1/24` and `fd00:168::1/64` (one per
family); it is mutually exclusive with `Pool`/`IPv6Pool`.

`Path` accepts an expanded path or a URI template. The default is
`/.well-known/masque/ip/{target}/{ipproto}/`, expanded to wildcard scope unless
`Target` and `IPProtocol` are set. Path variables and query operators
`{?target,ipproto}` / `{&target,ipproto}` are supported. A target can be an IP,
canonical CIDR or hostname; the server resolves hostnames and intersects the
result with permitted destinations. Custom paths must match at both ends.

## Routing and lifecycle

- `AdvertiseRoutes` on the server limits destinations, always including its
  allocation pools. Empty permits all destinations for allocated IP families.
  Client `AdvertiseRoutes` announces subnets reachable through that client.
  The server validates sources, routes between clients and decrements hop limits.
  The latest advertisement wins when advertised ranges overlap; an assigned
  client address takes precedence over advertisements.
- Advertisements alone do not create an external route. Configure Session port
  forwards for specific services, or supply `ForwardPacket(ctx, packet)` and use
  `Client.WritePacket` / `Server.WritePacket` for return traffic from a userspace
  router. The callback receives an owned packet before external forwarding;
  that router is responsible for hop-limit handling toward its external network.
  `WritePacket` decrements the hop limit toward the tunnel. No host NAT or TUN
  setup is performed. Packet callbacks must honor context cancellation.
- `Start` establishes the initial tunnel synchronously and returns initial errors.
  Once established, reconnection uses exponential backoff from `ReconnectInitial`
  (1 second) to `ReconnectMax` (1 minute). `DisableReconnect` disables automatic
  recovery. The Session persists; packets while disconnected are discarded.
- `Suspend`, `Resume` and `RestartSession` explicitly control the connection.
  `Ready`, `WaitReady(ctx)` and `Configuration()` expose current state.
  `Client.DialContext` fails while disconnected unless `OnDemand` is set, in
  which case it resumes and waits. Direct Session calls bypass this readiness gate.
- Live ADDRESS_ASSIGN updates replace protocol addresses while retaining the
  userspace stack and registered port-forward aliases. Removed addresses can
  invalidate existing sockets. `ConfigurationChanged` receives detached snapshots
  on activation and address/route updates; callbacks must not block or synchronously
  call `Close`/`WaitReady`. Poll `Configuration()` for disconnect/suspend state.
- ICMP reports route, source-policy, hop-limit and packet-size failures. HTTP/3
  defaults its initial QUIC packet size to MTU+51. A QUIC datagram size error
  generates PTB when the available IP payload is at least 1280 bytes; smaller
  capacity terminates the tunnel. Other transports use capsules.

The examples expose `-advertise-route` (repeatable), client `-target` / `-ipproto`,
`-disable-version-fallback`, `-disable-reconnect` and `-on-demand`. The server
example's demonstration services use `192.168.168.1`, so retain its default pool
when testing those services.

## Client extensions

Vendor-specific behavior is opt-in:

- `TLSConfig`: cloned per connection; supports client certificates and verification
  callbacks. Explicit `CA` and `ServerName` override the clone. `SkipVerify=true`
  enables insecure verification; false preserves the supplied TLS configuration.
  ALPN is selected by the chosen transport.
- `ConnectURL`: full HTTPS URL, separate from the `Server:Port` dial address and
  TLS SNI. Overrides `Path`. Userinfo, fragments and unexpanded templates are rejected.
- `Protocol`: Extended CONNECT token (default `connect-ip`), for HTTP/2 and HTTP/3.
- `Headers`: cloned CONNECT headers. Pseudo/hop-by-hop headers are rejected;
  `Capsule-Protocol` is managed internally, and Basic credentials override Authorization.
- `HTTP3.QUICConfig`: cloned quic-go configuration for transport tuning; datagrams
  remain enabled. Also supported by the server.
- `HTTP3.AdditionalSettings` and `HTTP3.ConnectionIDLength`: private SETTINGS and
  QUIC connection ID length. Reserved settings and out-of-range values are rejected.
- `AllowMissingExtendedConnect`: explicitly permit a missing peer enabling setting.
  This does not disable TLS verification, HTTP status checks or capsule validation.
- `Addresses`: static **host IPs**, not subnets. Suppresses ADDRESS_REQUEST and the
  initial ADDRESS_ASSIGN wait. Subsequent assignments update the Session.

For example, a private CONNECT-IP deployment can configure:

```go
config := masque.Config{
	Version:    3,
	Server:     "192.0.2.1",
	Port:       443,
	ServerName: "tls.example.com",
	ConnectURL: "https://proxy.example.com/tunnel",
	Protocol:   "vendor-ip",
	TLSConfig:  &tls.Config{Certificates: []tls.Certificate{clientCertificate}},
	Headers:    http.Header{"X-Client": {"example"}},
	Addresses:  []netip.Addr{netip.MustParseAddr("192.0.2.2")},
}
```

`TunnelDialer` / `TunnelDialFunc` can replace establishment entirely or delegate
its prepared `DialRequest` to `DefaultTunnelDialer`. The returned `Tunnel` exposes
standard RFC 9484 capsule bytes. An optional `DatagramTunnel` exposes a context ID
varint followed by an IP packet; QUIC stream IDs and private framing belong in the
adapter. `ErrDatagramsUnavailable` and `ErrDatagramTooLarge` request capsule fallback.
The dial context ends after startup; established streams must survive that context
being canceled and release resources via `Close`. Close must unblock concurrent I/O.
More substantial wire changes must be translated by the adapter.

These hooks do not implement account registration. The standalone build example
in `examples/build/cmd/masque_client` adds an explicit WARP HTTP/3 profile that reads
an existing usque JSON configuration; the standard library remains vendor-neutral.
