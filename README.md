# govpn

Pure-Go VPN clients and servers backed by a private gVisor network stack.

- WireGuard, SSTP, OpenVPN, native SoftEther, OpenSSH TUN, L2TP/IPsec, and MASQUE CONNECT-IP (HTTP/1.1, HTTP/2, HTTP/3)
- no CGO
- no `/dev/tun` or TUN/TAP interface
- no root privileges or host route changes
- TCP and UDP through the standard Go network interfaces

## Install

```sh
go get github.com/bclswl0827/govpn
```

## API

All clients and servers implement the same lifecycle:

```go
type Starter interface {
	Start(context.Context) (*govpn.Session, error)
}
```

A session provides sockets inside the VPN network:

```go
session, err := client.Start(ctx)
if err != nil {
	return err
}
defer session.Close()

conn, err := session.DialContext(ctx, "tcp", "10.0.0.1:443")
listener, err := session.Listen("tcp", "10.0.0.2:8080")
packetConn, err := session.ListenPacket("udp", "10.0.0.2:5353")
```

These sockets are not visible on the host. Use an explicit proxy when a host
application needs access to a session socket.

ICMP is available through the same userspace stack. The connection carries
ICMP messages, not host raw sockets:

```go
conn, err := session.DialICMP4("10.0.0.1")
if err != nil {
	return err
}
defer conn.Close()

if err := conn.SetTTL(1); err != nil {
	return err
}
_, err = conn.Write([]byte{8, 0, 0, 0, 0, 1, 0, 1})
```

`ReadFrom` returns the ICMP message and the source IP. Use type 0 replies for
ping and type 11 (IPv4) or type 3 (IPv6) errors for traceroute. IPv4 checksums
are filled automatically. `DialICMP6` and `SetHopLimit` provide the IPv6
equivalent. Traceroute replies from intermediate routers are delivered as
usual. This does not redirect the host `ping` command.

## Host port forwarding

`RegisterPortForward` exposes a host service at the VPN address assigned to the
userspace stack. In this example, the VPN address is `172.20.0.2` and the host
service is `10.0.0.200:8080`.

```go
forward, err := session.RegisterPortForward(ctx, govpn.PortForwardSpec{
	Network:       "tcp4",
	ListenAddress: "172.20.0.2:18080",
	TargetAddress: "10.0.0.200:8080",
})
if err != nil {
	return err
}
defer forward.Close()
```

The remote peer connects to `172.20.0.2:18080`. The listen address belongs to
the userspace VPN stack; the target address is reached through the host
network. Registering a forward does not change host routes, firewall rules, or
DNS settings.

To preserve the host address as the remote destination, use
`ListenAddress: "10.0.0.200:8080"` instead. The VPN peer must then route
`10.0.0.200/32` to this peer.

## WireGuard client

```go
package main

import (
	"context"
	"log"

	"github.com/bclswl0827/govpn/protocols/wireguard"
)

func main() {
	ctx := context.Background()
	client := wireguard.NewClient(wireguard.Config{
		PrivateKey: "CLIENT_PRIVATE_KEY",
		Address:    []string{"10.0.0.2/24"},
		Peers: []wireguard.Peer{{
			PublicKey:  "SERVER_PUBLIC_KEY",
			Endpoint:   "vpn.example.com:51820",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	})

	session, err := client.Start(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	conn, err := session.DialContext(ctx, "tcp", "10.0.0.1:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
```

WireGuard configuration files can also be loaded with
`wireguard.ParseConfigFile`. Runtime state and peer updates are available
through `Client.Runtime`, `Client.Status`, and the raw UAPI methods.

For a dual-stack peer endpoint, the optional `EndpointPreference` peer setting
controls DNS candidate order: `auto` keeps resolver order, `ipv4` prefers A
records, and `ipv6` prefers AAAA records. The default is `auto`. Before the
first successful handshake, govpn automatically tries the next resolved
address when the current candidate does not respond.

## SSH TUN client and server

The SSH client opens an OpenSSH `tun@openssh.com` point-to-point channel. Its
local endpoint is the private gVisor stack, so it does not create a local TUN
interface or require root privileges. It can connect either to the pure-Go
govpn SSH server or to OpenSSH. An OpenSSH server creates a remote TUN
interface and must allow it in `sshd_config`:

```text
PermitTunnel point-to-point
```

Use a fixed remote unit when a setup command needs a predictable interface:

```go
unit := 0
client := sshvpn.NewClient(sshvpn.Config{
	Server:         "vpn.example.com:22",
	User:           "vpn",
	PrivateKey:     privateKey,
	KnownHostsFile: "/home/user/.ssh/known_hosts",
	Address:        []string{"10.90.0.2/30", "fd90::2/126"},
	RemoteTunnel:   &unit,
	RemoteCommand:  "sudo ip addr add 10.90.0.1 peer 10.90.0.2 dev tun0 && sudo ip link set tun0 up",
})
session, err := client.Start(ctx)
```

The remote host must separately configure forwarding and routing or NAT for
the traffic it should carry. IPv6 works over the same channel when the remote
TUN has an IPv6 address and the server has an IPv6 route for the delegated
prefix. `RemoteCommand` is optional and requires suitable remote permissions.

The govpn SSH server terminates the same channel directly in its private
gVisor stack. Neither side uses `/dev/tun`:

```go
server := sshvpn.NewServer(sshvpn.ServerConfig{
	ListenIP:   "0.0.0.0",
	ListenPort: 2222,
	HostKey:    hostPrivateKey,
	Users: map[string]sshvpn.ServerUser{
		"alice": {Password: "secret"},
	},
	Address: []string{"10.90.0.1/30", "fd90::1/126"},
})
session, err := server.Start(ctx)
```

`ResolveTunnel` can select addresses and MTU from the authenticated user,
public-key permissions, or requested logical TUN unit. The server is also an
extensible SSH transport:

```go
server.RegisterChannelHandler("direct-tcpip", directTCPIPHandler)
server.RegisterGlobalRequestHandler("tcpip-forward", forwardingHandler)
server.RegisterSessionRequestHandler("pty-req", ptyHandler)
server.RegisterSessionRequestHandler("shell", shellHandler)
server.RegisterSessionRequestHandler("subsystem", sftpHandler)
```

Channel and request handlers receive the native `x/crypto/ssh` objects and own
accept/reject or reply behavior. `ServerSession` provides per-session state so
a PTY request can share state with a later shell or exec request.
`Server.Serve(ctx, listener)` accepts one tunnel connection. General-purpose
or multi-client SSH servers can accept connections themselves and call
`Server.HandleConn`; registered shell and SFTP handlers then work with or
without a TUN channel. The complete server example includes PTY, resize,
signal forwarding, SFTP, concurrent connections, and userspace tunnels.

## MASQUE client and server

MASQUE carries IP packets over TLS HTTP/1.1 Upgrade, HTTP/2 Extended CONNECT,
or HTTP/3 CONNECT-IP. HTTP/3 uses QUIC datagrams with capsule fallback;
HTTP/1.1 and HTTP/2 carry packets in capsules. Both sides use the same private
gVisor stack and Session API as the other protocols.

```go
client := masque.NewClient(masque.Config{
	Server:   "vpn.example.com",
	Port:     443,
	Version:  3,
	Username: "alice",
	Password: "secret",
	CA:       caPEM,
})
session, err := client.Start(ctx)
```

The server assigns IPv4 and/or IPv6 addresses from its configured pools:

```go
server := masque.NewServer(masque.ServerConfig{
	ListenIP:   "0.0.0.0",
	ListenPort: 443,
	Versions:   []int{1, 2, 3},
	Cert:       certPEM,
	Key:        keyPEM,
	Users:      map[string]string{"alice": "secret"},
	Pool:       "192.168.168.0/24",
	IPv6Pool:   "fd00:168::/64",
})
session, err := server.Start(ctx)
```

`Config.Version` selects 1, 2, or 3; zero defaults to HTTP/3. Transport
unavailability permits fallback to lower versions unless `DisableVersionFallback`
is set; authentication and certificate failures do not. `ServerConfig.Versions`
defaults to all three, sharing a port number across TCP and UDP. `Path` accepts
URI templates and defaults to `/.well-known/masque/ip/{target}/{ipproto}/`.
Certificates and CA are PEM bytes; `MTU` defaults to 1280.

The server allocates distinct addresses to concurrent clients and releases them
on disconnect. Both sides support route advertisements, destination/protocol
scope, ICMP errors and client-subnet forwarding. Established clients reconnect
with exponential backoff and apply new addresses to the existing Session.
`Suspend`, `Resume`, `RestartSession`, `Ready` and `WaitReady` control lifecycle;
use the Client socket methods for readiness-aware dialing. `ForwardPacket` and
`WritePacket` integrate external userspace routers without installing host routes.

Client extensions include custom TLS configuration, CONNECT URLs, headers,
protocol identifiers, static addresses, and explicit HTTP/3 compatibility
options. `TunnelDialer` can replace connection establishment while retaining
the capsule processing and userspace stack. See the
[MASQUE examples and configuration](examples/masque/README.md).

## Protocols

| Package               | Implementation                                                                        |
| --------------------- | ------------------------------------------------------------------------------------- |
| `protocols/wireguard` | Official `wireguard-go` engine, IPv4/IPv6, PSK, roaming, keepalive, runtime UAPI      |
| `protocols/sstp`      | TLS, SSTP, PPP, LCP, PAP, IPCP, crypto binding                                        |
| `protocols/openvpn`   | UDP/TCP IPv4/IPv6, TLS, `tls-auth`, `tls-crypt`, AEAD/CBC ciphers, LZO                |
| `protocols/softether` | Native SoftEther HTTPS/PACK login and Ethernet data channel                           |
| `protocols/ssh`       | Pure-Go SSH TUN client/server, IPv4/IPv6, extensible channel/request dispatch         |
| `protocols/l2tp`      | IKEv1 PSK, NAT-T, ESP transport mode, L2TPv2, PPP, MS-CHAPv2, IPCP/IPv4 client/server |
| `protocols/masque`    | TLS HTTP/1.1 Upgrade, HTTP/2 and HTTP/3 CONNECT-IP, Basic auth, IPv4/IPv6, client extensions |

The VPN protocol packages provide `NewClient` and `NewServer`. Complete
programs are under `examples/`:

```sh
go run ./examples/wireguard/client -h
go run ./examples/wireguard/server -h
go run ./examples/sstp/client -h
go run ./examples/openvpn/client -h
go run ./examples/softether/client -h
go run ./examples/ssh/client -h
go run ./examples/ssh/server -h
go run ./examples/l2tp/client -h
go run ./examples/l2tp/server -h
go run ./examples/masque/client -h
go run ./examples/masque/server -h
```

All client/server examples use `192.168.168.0/24`. Servers expose
`http://192.168.168.1/`, while clients start a local SOCKS5 listener and print
curl commands for both the internal HTTP service and WAN egress through the
VPN server. See [`examples/README.md`](examples/README.md).

## Limits

- `wg-quick` routes, DNS changes, firewall rules, and lifecycle scripts are
  parsed but not applied to the host.
- SSTP supports PAP authentication; MS-CHAPv2, EAP, and IPv6CP are not yet
  implemented.
- SoftEther does not provide UDP acceleration, R-UDP bulk mode, additional TCP
  connections, half connections, or QoS.
- Connecting the SSH client to OpenSSH requires `PermitTunnel point-to-point`
  and remote interface/routing configuration. OpenSSH interoperability
  currently targets Linux `IFF_TUN | IFF_NO_PI` framing. The pure-Go govpn
  client/server path has no OS TUN dependency.
- L2TP/IPsec supports IKEv1 Main Mode with PSK, NAT-T, AES-CBC, L2TPv2,
  MS-CHAPv2, and IPCP/IPv4. IPv6 and IKEv2 are not implemented.
- MASQUE implements CONNECT-IP; CONNECT-UDP is a separate protocol and is not
  implemented. Servers expose userspace sockets and explicit packet-forwarding
  hooks without configuring host routing or NAT. Reconnection preserves the
  Session, but does not guarantee survival of sockets bound to revoked addresses.

Unsupported settings return an error instead of being ignored.

## Test

```sh
CGO_ENABLED=0 go test -buildvcs=false ./...
```

The protocol tests run local userspace client/server pairs. WireGuard also has
direct interoperability tests against the official `wireguard-go` engine.
