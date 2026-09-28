# IKEv2 example

Start the responder and initiator in separate terminals:

```sh
go run ./examples/ikev2/server -psk 'replace-with-a-random-secret'
go run ./examples/ikev2/client -server 127.0.0.1 \
  -psk 'replace-with-a-random-secret'
```

The default identities are `alice` and `vpn.example`. Identity matching is
exact; set `-client-id` and `-server-id` on both commands when changing them.
Unprefixed names use ID_FQDN; `ipv4:`, `email:`, `fqdn:`, and `keyid:` prefixes
can select an explicit IKE identity type for an external peer.
The server allocates `192.168.168.2` from the example pool. The client exposes
the standard example SOCKS5 proxy on `127.0.0.1:1080`.

For an external peer, configure IKEv2 PSK authentication and this proposal:

```text
IKE: aes256-sha256-modp2048
ESP: aes256-sha256
```

Username/password authentication uses EAP-MSCHAPv2 and authenticates the
responder with an RSA certificate. Start a govpn pair with:

```sh
go run ./examples/ikev2/server \
  -username alice -password secret \
  -cert server-cert.pem -key server-key.pem
go run ./examples/ikev2/client -server 127.0.0.1 \
  -username alice -password secret -ca ca-cert.pem
```

The implementation requests an IPv4 virtual address and negotiates IPv4
tunnel mode. UDP encapsulation is forced by default because govpn has no raw
ESP socket and does not install kernel IPsec state. Allow UDP/500 and UDP/4500
to the server. The implementation follows RFC 7296, RFC 3948, and RFC 4303,
with the RFC 8247/RFC 8221 mandatory algorithm suite. PSK and
EAP-MSCHAPv2/RSA-certificate authentication are supported. Generic client
certificate authentication, other EAP methods, IPv6, IKE fragmentation,
MOBIKE, and Child SA rekeying are not currently supported.
