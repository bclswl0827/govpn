// Package l2tp implements L2TP/IPsec client and server roles using IKEv1
// pre-shared-key authentication, NAT-T, ESP transport mode, L2TPv2, and PPP
// MS-CHAPv2.
package l2tp

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/bclswl0827/govpn"
)

const (
	defaultIKEPort  = 500
	defaultNATTPort = 4500
	defaultMTU      = 1400
)

// ErrServerUnsupported is retained for source compatibility. Implemented
// servers no longer return it.
//
// Deprecated: L2TP/IPsec server support is implemented.
var ErrServerUnsupported = errors.New("l2tp: server is not supported")

// Config configures an L2TP/IPsec client.
type Config struct {
	Server   string
	IKEPort  int
	PSK      string
	Username string
	Password string
	MTU      int
	Timeout  time.Duration
	Logger   *log.Logger
}

// ServerConfig configures an L2TP/IPsec responder.
type ServerConfig struct {
	ListenIP string
	// PublicIP is the outer address clients use. It defaults to ListenIP when
	// ListenIP is concrete and is required for a wildcard listener.
	PublicIP          string
	IKEPort           int
	NATTPort          int
	PSK               string
	Users             map[string]string
	Pool              string
	DNS               []net.IP
	MTU               int
	Logger            *log.Logger
	TrafficPolicy     govpn.TrafficPolicy
	OnTrafficDecision govpn.TrafficPolicyCallback
}
