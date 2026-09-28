package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"time"

	"github.com/bclswl0827/govpn"
	"golang.org/x/crypto/curve25519"
)

const defaultMTU = 1420

type EndpointPreference string

const (
	EndpointPreferenceAuto EndpointPreference = "auto"
	EndpointPreferenceIPv4 EndpointPreference = "ipv4"
	EndpointPreferenceIPv6 EndpointPreference = "ipv6"
)

type Peer struct {
	PublicKey          string             `json:"public-key"`
	PresharedKey       string             `json:"preshared-key,omitempty"`
	Endpoint           string             `json:"endpoint,omitempty"`
	EndpointPreference EndpointPreference `json:"endpoint-preference,omitempty"`
	AllowedIPs         []string           `json:"allowed-ips,omitempty"`
	Keepalive          int                `json:"persistent-keepalive,omitempty"`

	endpointCandidates []string
}

// PeerUpdate describes an incremental update using the official WireGuard
// cross-platform UAPI semantics. Nil pointer fields are left unchanged. An
// empty PresharedKey clears the existing key, and a zero Keepalive disables
// persistent keepalives.
type PeerUpdate struct {
	PublicKey         string
	UpdateOnly        bool
	Remove            bool
	PresharedKey      *string
	Endpoint          *string
	Keepalive         *int
	ReplaceAllowedIPs bool
	AllowedIPs        []string
	RemoveAllowedIPs  []string
}

type Config struct {
	PrivateKey   string
	Address      []string
	DNS          []string
	MTU          int
	ListenPort   int
	FirewallMark uint32
	Peers        []Peer
	Table        string
	PreUp        []string
	PostUp       []string
	PreDown      []string
	PostDown     []string
	SaveConfig   bool
	Logger       *log.Logger
}

type ServerPeer = Peer

type ServerConfig struct {
	PrivateKey string
	ListenPort int
	// ListenIP is retained for configuration compatibility. wireguard-go binds
	// both wildcard families; a specific bind address is not supported.
	ListenIP          string
	Address           string
	Address6          string
	Addresses         []string
	MTU               int
	FirewallMark      uint32
	Peers             []ServerPeer
	Logger            *log.Logger
	TrafficPolicy     govpn.TrafficPolicy
	OnTrafficDecision govpn.TrafficPolicyCallback
}

func GenerateKeypair() (privateKey, publicKey string, err error) {
	privateKey, err = GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	publicKey, err = PublicKey(privateKey)
	return privateKey, publicKey, err
}

func GeneratePrivateKey() (string, error) {
	key := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	key[0] &= 248
	key[31] = key[31]&127 | 64
	return base64.StdEncoding.EncodeToString(key), nil
}

func GeneratePresharedKey() (string, error) {
	key := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func PublicKey(privateKey string) (string, error) {
	private, err := decodeKey(privateKey)
	if err != nil {
		return "", err
	}
	zero := true
	for _, value := range private {
		zero = zero && value == 0
	}
	if zero {
		return "", errors.New("wireguard: private key is all zero")
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

type Status struct {
	PublicKey    string
	ListenPort   int
	FirewallMark uint32
	Peers        []PeerStatus
}

type PeerStatus struct {
	PublicKey     string
	Endpoint      string
	AllowedIPs    []string
	Keepalive     int
	LastHandshake time.Time
	TransmitBytes uint64
	ReceiveBytes  uint64
}
