# Third-party notices

WireGuard uses the official pure-Go protocol engine from
`golang.zx2c4.com/wireguard`, licensed under the MIT License.

gVisor is consumed as a Go module under the Apache License 2.0.

OpenVPN LZO1X decompression uses the pure-Go `github.com/anchore/go-lzo`
module, licensed under the MIT License.

The SSTP and OpenVPN wire implementations in this repository were written
from the published Microsoft SSTP/PPP RFCs and official OpenVPN protocol
documentation. SoftEther has no published RFC; its wire implementation was
written against the behavior and data formats of the official SoftEtherVPN
source tree. No SoftEtherVPN C source is copied into this project.

The L2TP/IPsec IKEv1, ESP, L2TP, PPP, and MS-CHAPv2 client core is adapted
from `github.com/xen0bit/veepin`, copyright (c) 2026 Remy, under the MIT License.

MASQUE HTTP/3 uses `github.com/quic-go/quic-go` and
`github.com/quic-go/qpack`, licensed under the MIT License. HTTP/2 uses
the public Framer and HPACK APIs from `golang.org/x/net/http2`, licensed
under the BSD 3-Clause License.
