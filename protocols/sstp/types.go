package sstp

import (
	"log"
	"net"

	"github.com/bclswl0827/govpn"
)

const defaultMTU = 1500

type Config struct {
	Server       string
	Port         int
	Username     string
	Password     string
	CA           []byte
	ServerName   string
	SkipVerify   bool
	PrefixLength int
	Logger       *log.Logger
}

type ServerConfig struct {
	Cert       []byte
	Key        []byte
	ListenIP   string
	ListenPort int
	Pool       string
	DNS        []net.IP
	Users      map[string]string
	// Shape is retained for source compatibility and rejected when non-zero;
	// traffic shaping is not part of SSTP.
	Shape             int
	Logger            *log.Logger
	TrafficPolicy     govpn.TrafficPolicy
	OnTrafficDecision govpn.TrafficPolicyCallback
}
