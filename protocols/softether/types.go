package softether

import (
	"log"
	"time"

	"github.com/bclswl0827/govpn"
)

const defaultMTU = 1500

type AuthType uint32

const (
	AuthPassword AuthType = iota
	AuthPlainPassword
	AuthAnonymous
	AuthCertificate AuthType = 3
)

type Config struct {
	Server            string
	Port              int
	Hub               string
	Username          string
	Password          string
	AuthType          AuthType
	ClientCert        []byte
	ClientKey         []byte
	Address           string
	Gateway           string
	CA                []byte
	ServerName        string
	SkipVerify        bool
	OpenSSLCompat     bool
	MaxConnections    int
	DisableEncryption bool
	EnableCompression bool
	HalfConnection    bool
	EnableQoS         bool
	ConnectTimeout    time.Duration
	DHCPTimeout       time.Duration
	Logger            *log.Logger
}

type ServerConfig struct {
	Cert              []byte
	Key               []byte
	ListenIP          string
	ListenPort        int
	Hub               string
	Pool              string
	Users             map[string]string
	AnonymousUsers    map[string]bool
	UserCertificates  map[string][]byte
	DNS               []string
	EnableCompression bool
	DisableEncryption bool
	MaxConnections    int
	MTU               int
	Logger            *log.Logger
	TrafficPolicy     govpn.TrafficPolicy
	OnTrafficDecision govpn.TrafficPolicyCallback
}
