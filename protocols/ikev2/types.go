// Package ikev2 implements a pure-Go IKEv2/IPsec client and server.
//
// The package supports pre-shared keys and EAP-MSCHAPv2 username/password
// authentication, IPv4 configuration payloads, NAT traversal, and an ESP
// tunnel-mode data path. It never creates a host TUN device or installs kernel
// IPsec state.
package ikev2

import (
	"log"
	"net"
	"time"

	"github.com/bclswl0827/govpn"
)

const (
	defaultIKEPort  = 500
	defaultNATTPort = 4500
	defaultMTU      = 1400
	defaultPool     = "10.60.0.0/24"
)

// Config configures an IKEv2 initiator.
type Config struct {
	Server   string
	IKEPort  int
	NATTPort int

	// LocalID is sent in IDi. RemoteID is the required responder identity.
	// Values infer IPv4, RFC822, or FQDN form; the explicit prefixes ipv4:,
	// email:, fqdn:, and keyid: select a specific IKE identity type.
	LocalID  string
	RemoteID string
	PSK      string

	// Username and Password select EAP-MSCHAPv2 authentication. They are
	// mutually exclusive with PSK. CA contains one or more PEM-encoded CA
	// certificates used to authenticate the responder certificate. ServerName
	// overrides the certificate name inferred from RemoteID. SkipVerify skips
	// only certificate chain and name verification; the responder's IKE AUTH
	// signature is always verified.
	Username   string
	Password   string
	CA         []byte
	ServerName string
	SkipVerify bool

	MTU     int
	Timeout time.Duration
	Logger  *log.Logger

	// DisableForceEncapsulation disables the default forced NAT-T behavior.
	// Pure-Go ESP cannot use raw IP without elevated host privileges, so this
	// should only be set when a custom peer is known to encapsulate ESP in UDP
	// even without NAT detection.
	DisableForceEncapsulation bool

	// AllowLegacyMODP1024 explicitly enables the obsolete 1024-bit MODP group
	// required by some legacy peers. When enabled, it is used instead of the
	// default MODP-2048 group.
	AllowLegacyMODP1024 bool
}

// ServerConfig configures an IKEv2 responder.
type ServerConfig struct {
	ListenIP string
	// PublicIP is the outer IPv4 address used in NAT detection. It defaults to
	// ListenIP when ListenIP is concrete and is required for a wildcard bind.
	PublicIP string
	IKEPort  int
	NATTPort int

	// Identity is sent in IDr. Users maps accepted initiator identities to
	// their pre-shared keys. Identity values accept the same explicit type
	// prefixes as Config.LocalID.
	Identity string
	Users    map[string]string

	// PasswordUsers maps EAP-MSCHAPv2 usernames to passwords. Certificate and
	// PrivateKey are the PEM-encoded responder certificate chain (leaf first)
	// and RSA private key used to authenticate the responder in EAP mode.
	PasswordUsers map[string]string
	Certificate   []byte
	PrivateKey    []byte

	Pool string
	DNS  []net.IP
	MTU  int

	Logger            *log.Logger
	TrafficPolicy     govpn.TrafficPolicy
	OnTrafficDecision govpn.TrafficPolicyCallback

	// DisableForceEncapsulation has the same meaning as on Config. The default
	// deliberately causes NAT detection so ESP stays on unprivileged UDP.
	DisableForceEncapsulation bool

	// AllowLegacyMODP1024 allows initiators to negotiate the obsolete 1024-bit
	// MODP group. It is disabled by default.
	AllowLegacyMODP1024 bool
}
