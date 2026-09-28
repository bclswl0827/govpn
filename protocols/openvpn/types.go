package openvpn

import (
	"log"
	"net"

	"github.com/bclswl0827/govpn"
)

const defaultMTU = 1500

type Remote struct {
	Host     string
	Port     int
	Protocol string
}

type Config struct {
	Remote             string
	Remotes            []Remote
	Port               int
	Protocol           string
	CA                 []byte
	Cert               []byte
	Key                []byte
	PeerFingerprints   [][]byte
	VerifyX509Name     string
	VerifyX509Type     string
	RemoteCertTLS      string
	TLSVersionMin      uint16
	TLSVersionMax      uint16
	Cipher             string
	DataCiphers        []string
	DataCipherFallback string
	Auth               string
	TLSAuth            []byte
	TLSCrypt           []byte
	KeyDirection       int
	KeyDirectionSet    bool
	Username           string
	Password           string
	Compression        string
	MTU                int
	Shape              int
	IgnoredDirectives  []string
	Logger             *log.Logger
}

type ServerConfig struct {
	CA                 []byte
	Cert               []byte
	Key                []byte
	TLSVersionMin      uint16
	TLSVersionMax      uint16
	VerifyClientCert   string
	ListenIP           string
	ListenPort         int
	Protocol           string
	Pool               string
	Pool6              string
	DNS                []net.IP
	MTU                int
	Cipher             string
	DataCiphers        []string
	DataCipherFallback string
	Compression        string
	TLSCrypt           []byte
	TLSAuth            []byte
	Auth               string
	KeyDirection       int
	KeyDirectionSet    bool
	Shape              int
	Logger             *log.Logger
	TrafficPolicy      govpn.TrafficPolicy
	OnTrafficDecision  govpn.TrafficPolicyCallback
}
