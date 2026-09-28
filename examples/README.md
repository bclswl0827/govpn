# govpn examples

Every client/server example uses the same userspace network and application
behavior:

- `192.168.168.0/24` is the VPN network;
- `192.168.168.1` is the server address;
- the server exposes `http://192.168.168.1/` and returns `VPN works!`;
- the client listens for SOCKS5 on `127.0.0.1:1080` by default;
- public SOCKS5 destinations leave through the VPN server's host network;
- every server example uses the same blacklist to deny `example.com` and its
  subdomains together with OpenDNS (`208.67.220.220`, `208.67.222.222`),
  and logs the denied policy decision.

After a client connects, it prints commands equivalent to:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://192.168.168.1/
curl --socks5-hostname 127.0.0.1:1080 https://github.com/
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
curl --socks5-hostname 127.0.0.1:1080 http://208.67.220.220/
```

The first command verifies access to the server's userspace HTTP service. The
second verifies WAN egress through the server. The third and forth are rejected by the
shared `TrafficPolicy` blacklist and produces a `[traffic-policy]` server log.
No host IP forwarding or NAT is required: permitted public requests are chained
to an egress SOCKS5 endpoint reachable only inside the VPN.

The example rules match hostnames (`DestinationHosts`) and IP CIDRs
(`DestinationPrefixes`) on the server-side SOCKS5 egress path. It demonstrates hostname policy but is not a strict security boundary:
a client can request an IP literal, and website addresses can change or be
shared by a CDN. Production policies should use destination CIDR rules or a
default-deny CIDR allowlist. The shared rule and callback are defined in
`examples/internal/exampleutil` and are used by every protocol server example.

Authentication flags use common names where the protocols have equivalent
concepts: `-username`, `-password`, `-cert`, `-key`, and
`-insecure-skip-verify`. Protocol-specific credentials such as WireGuard keys,
an IPsec PSK, and an SSH host key retain explicit names.

OpenVPN, SSTP, SoftEther, L2TP, IKEv2, and MASQUE obtain `192.168.168.2` from their
server-side configuration protocols. WireGuard and SSH TUN have no
address-assignment exchange, so their examples configure `192.168.168.2/24`
statically.

## Protocol examples

Run each command with `-h` to view its configuration flags:

| Protocol    | Client                                  | Server                                  |
| ----------- | --------------------------------------- | --------------------------------------- |
| WireGuard   | `go run ./examples/wireguard/client -h` | `go run ./examples/wireguard/server -h` |
| SSTP        | `go run ./examples/sstp/client -h`      | `go run ./examples/sstp/server -h`      |
| OpenVPN     | `go run ./examples/openvpn/client -h`   | `go run ./examples/openvpn/server -h`   |
| SoftEther   | `go run ./examples/softether/client -h` | `go run ./examples/softether/server -h` |
| SSH TUN     | `go run ./examples/ssh/client -h`       | `go run ./examples/ssh/server -h`       |
| L2TP/IPsec  | `go run ./examples/l2tp/client -h`      | `go run ./examples/l2tp/server -h`      |
| IKEv2/IPsec | `go run ./examples/ikev2/client -h`     | `go run ./examples/ikev2/server -h`     |
| MASQUE      | `go run ./examples/masque/client -h`    | `go run ./examples/masque/server -h`    |

See [ikev2/README.md](ikev2/README.md) for the IKE/ESP proposal and external
peer requirements. See [masque/README.md](masque/README.md) for certificate
setup, HTTP version selection, and extended client configuration.
