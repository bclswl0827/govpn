// Package masque implements CONNECT-IP over TLS HTTP/1.1 Upgrade, HTTP/2
// Extended CONNECT, and HTTP/3 with QUIC datagrams and capsule fallback.
// CONNECT-UDP is a separate protocol and is not implemented.
package masque

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	DefaultPath = "/.well-known/masque/ip/*/*/"
	DefaultMTU  = 1280
)

// Tunnel carries RFC 9484 capsules. Close must be idempotent, safe alongside
// Read/Write and unblock both. Private wire formats must be translated by the adapter.
type Tunnel interface{ io.ReadWriteCloser }

// DatagramTunnel optionally carries RFC 9484 HTTP Datagram payloads: context ID
// varint followed by the IP packet. The adapter owns stream/quarter-stream IDs
// and any vendor framing; those MUST NOT appear in these payloads. Receive must
// honor ctx and Close; Send must unblock on Close. Reads and writes may overlap
// capsule I/O. ErrDatagramsUnavailable or ErrDatagramTooLarge requests capsule
// fallback for a send. When datagrams are unavailable, Receive should wait for
// cancellation or Close rather than return an error that terminates the tunnel.
type DatagramTunnel interface {
	Tunnel
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

// HTTP3Options are opt-in wire compatibility settings. Zero values retain the
// standard transport. AdditionalSettings cannot replace settings owned by HTTP/3.
type HTTP3Options struct {
	AdditionalSettings map[uint64]uint64
	ConnectionIDLength int // 0 uses quic-go's default; otherwise 1..20.
	// QUICConfig is cloned; datagrams are always enabled. A zero InitialPacketSize
	// is set to MTU+51 so the first datagrams can carry a minimum-sized IP packet.
	QUICConfig *quic.Config
}

// DialRequest is a per-connection snapshot. The dialer may mutate Request,
// TLSConfig and HTTP3.AdditionalSettings, but must not mutate objects referenced
// by TLSConfig (certificates, pools, callbacks). Request carries the configured
// CONNECT URL, headers and protocol in Proto, independently of Remote and SNI.
type DialRequest struct {
	Remote                      string
	Version                     int
	TLSConfig                   *tls.Config
	Request                     *http.Request
	HTTP3                       HTTP3Options
	AllowMissingExtendedConnect bool
}

// TunnelDialer replaces only connection establishment. ctx bounds the handshake
// and is canceled after Start returns: a successful tunnel MUST NOT retain ctx
// as its lifetime context. Close tears down all resources owned by the dialer.
// On error the dialer cleans up its resources; ownership transfers on success.
type TunnelDialer interface {
	DialTunnel(context.Context, DialRequest) (Tunnel, error)
}

// TunnelDialFunc adapts a function to TunnelDialer.
type TunnelDialFunc func(context.Context, DialRequest) (Tunnel, error)

func (f TunnelDialFunc) DialTunnel(ctx context.Context, request DialRequest) (Tunnel, error) {
	return f(ctx, request)
}

type Config struct {
	Version    int // 1, 2, or 3. Zero defaults to HTTP/3.
	Server     string
	Port       int // Defaults to 443.
	Username   string
	Password   string
	CA         []byte
	ServerName string
	SkipVerify bool
	Path       string // Expanded path or URI template; defaults to DefaultTemplate.
	MTU        int    // Defaults to 1280; must be between 1280 and 65535.
	Logger     *log.Logger

	// TLSConfig is cloned. Explicit CA/ServerName override its roots/name;
	// SkipVerify=true enables InsecureSkipVerify, false preserves TLSConfig's value.
	// TLS 1.2 minimum is used when MinVersion is zero; transport selects ALPN.
	TLSConfig *tls.Config
	// ConnectURL overrides Path and HTTP authority, not Server/Port or TLS SNI.
	// Must be an expanded HTTPS URL without userinfo or fragment.
	ConnectURL string
	// Protocol defaults to "connect-ip"; custom tokens require HTTP/2 or HTTP/3.
	Protocol string
	// Headers are cloned. Capsule-Protocol is owned by the implementation;
	// explicit Username/Password take precedence over Authorization.
	Headers http.Header
	// Addresses selects static host addresses: no ADDRESS_REQUEST is sent and
	// Start does not wait for ADDRESS_ASSIGN. Empty retains standard negotiation.
	// Dynamic ADDRESS_ASSIGN updates are applied to the existing Session.
	Addresses []netip.Addr
	HTTP3     HTTP3Options
	// AllowMissingExtendedConnect permits peers omitting the enabling setting.
	// Only affects HTTP/2 and HTTP/3 and must be explicitly opted into.
	AllowMissingExtendedConnect bool
	// DisableVersionFallback prevents retrying lower HTTP versions on transport
	// unavailability. Authentication, TLS validation and HTTP errors never fall back.
	DisableVersionFallback bool
	OnDemand               bool // DialContext resumes a suspended client before waiting for readiness.

	DisableReconnect bool          // By default retry failed established connections.
	ReconnectInitial time.Duration // Default 1 second.
	ReconnectMax     time.Duration // Default 1 minute.
	Target           string        // URI-template target: IP, prefix, hostname, or empty for *.
	IPProtocol       uint8         // URI-template ipproto; zero for *.
	AdvertiseRoutes  []netip.Prefix
	// ForwardPacket receives owned IP packets addressed to advertised subnets
	// outside the local Session. Use Client.WritePacket for packets returning
	// from an external router. Nil delivers to Session aliases/port forwards.
	ForwardPacket func(context.Context, []byte) error
	// ConfigurationChanged runs after address/route updates. Callbacks must not
	// block or call Close/WaitReady synchronously on the same client.
	ConfigurationChanged func(Configuration)

	// Dialer replaces establishment or translates a private wire format.
	Dialer TunnelDialer
}

// ServerConfig configures a multi-client CONNECT-IP endpoint. The server owns
// one userspace Session and allocates distinct addresses to connected clients.
// Empty Users allows unauthenticated access. No host routes or NAT are installed.
type ServerConfig struct {
	Versions   []int // Enabled HTTP versions; defaults to {1, 2, 3}.
	Cert       []byte
	Key        []byte
	ListenIP   string
	ListenPort int
	Pool       string
	IPv6Pool   string
	Users      map[string]string
	Path       string
	MTU        int
	Logger     *log.Logger
	// Address specifies server host addresses with their allocation prefix,
	// at most one per family. Mutually exclusive with legacy Pool/IPv6Pool.
	Address []netip.Prefix
	// AdvertiseRoutes permits these destinations plus the tunnel pools.
	// Empty allows all destinations of allocated address families.
	AdvertiseRoutes []netip.Prefix
	Resolve         func(context.Context, string) ([]netip.Addr, error)
	ForwardPacket   func(context.Context, []byte) error
	TLSConfig       *tls.Config
	HTTP3           HTTP3Options
}

// Configuration is a detached snapshot of the active client configuration.
type Configuration struct {
	Addresses        []netip.Prefix
	Routes           []Route
	RoutesAdvertised bool
	Ready            bool
}
