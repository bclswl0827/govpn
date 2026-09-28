package ssh

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	gossh "golang.org/x/crypto/ssh"
)

const defaultMTU = 1500

// Config describes an OpenSSH point-to-point TUN client. Address contains the
// local addresses used by the in-process network stack; the corresponding
// remote TUN addresses and routes must be configured on the SSH server.
type Config struct {
	Server               string
	User                 string
	Password             string
	PrivateKey           []byte
	PrivateKeyPassphrase []byte
	KnownHostsFile       string
	HostKey              []byte
	HostKeyCallback      gossh.HostKeyCallback
	InsecureSkipHostKey  bool
	Address              []string
	MTU                  int
	RemoteTunnel         *int
	RemoteCommand        string
	Timeout              time.Duration
	KeepaliveInterval    time.Duration
	Logger               *log.Logger
}

// ServerUser contains the built-in authentication methods for one SSH user.
// Applications needing certificates, external identity stores, or custom
// permissions can use ServerConfig callbacks instead.
type ServerUser struct {
	Password       string
	AuthorizedKeys [][]byte
}

// TunnelRequest is the OpenSSH TUN channel request. Unit may be
// TunnelUnitAny; it is a logical identifier because the pure-Go server does
// not create an operating-system TUN interface.
type TunnelRequest struct {
	Mode uint32
	Unit uint32
}

const (
	TunnelModePointToPoint uint32 = sshTunnelModePointToPoint
	TunnelUnitAny          uint32 = sshTunnelIDAny
)

// TunnelSettings selects the addresses and MTU of the server-side userspace
// stack for an authenticated connection.
type TunnelSettings struct {
	Address []string
	MTU     int
}

// TunnelResolver authorizes a TUN request and selects settings after SSH
// authentication has completed.
type TunnelResolver func(context.Context, *gossh.ServerConn, TunnelRequest) (TunnelSettings, error)

// TunnelSessionHandler receives a userspace VPN session opened on an
// otherwise general-purpose SSH connection. Implementations normally start
// services on the session and return without closing it.
type TunnelSessionHandler func(context.Context, *gossh.ServerConn, *govpn.Session)

// ChannelHandler owns an SSH channel request and must accept or reject it.
// It is used for channel types such as direct-tcpip.
type ChannelHandler func(context.Context, *gossh.ServerConn, gossh.NewChannel)

// GlobalRequestHandler owns an SSH global request, including sending a reply
// when Request.WantReply is true.
type GlobalRequestHandler func(context.Context, *gossh.ServerConn, *gossh.Request)

// SessionRequestHandler handles requests such as pty-req, shell, exec, and
// subsystem on an accepted SSH session channel. It owns the request reply.
type SessionRequestHandler func(context.Context, *ServerSession, *gossh.Request)

// ServerSession is shared by all request handlers for one SSH session
// channel. Values allows PTY, shell, exec, and subsystem extensions to share
// per-session state without global maps.
type ServerSession struct {
	Connection *gossh.ServerConn
	Channel    gossh.Channel

	valuesMu sync.RWMutex
	values   map[string]any
}

// SetValue stores extension state shared by handlers for this session.
func (s *ServerSession) SetValue(key string, value any) {
	s.valuesMu.Lock()
	defer s.valuesMu.Unlock()
	if s.values == nil {
		s.values = make(map[string]any)
	}
	s.values[key] = value
}

// Value loads extension state shared by handlers for this session.
func (s *ServerSession) Value(key string) (any, bool) {
	s.valuesMu.RLock()
	defer s.valuesMu.RUnlock()
	value, ok := s.values[key]
	return value, ok
}

// ServerConfig describes a pure-Go SSH server. Address is used when
// ResolveTunnel is nil. The callbacks use the native x/crypto/ssh API so an
// application can attach permissions and external authentication state.
type ServerConfig struct {
	ListenIP                    string
	ListenPort                  int
	HostKey                     []byte
	HostKeyPassphrase           []byte
	Users                       map[string]ServerUser
	PasswordCallback            func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error)
	PublicKeyCallback           func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error)
	KeyboardInteractiveCallback func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error)
	NoClientAuth                bool
	Address                     []string
	MTU                         int
	ResolveTunnel               TunnelResolver
	Timeout                     time.Duration
	KeepaliveInterval           time.Duration
	ServerVersion               string
	Logger                      *log.Logger
	TrafficPolicy               govpn.TrafficPolicy
	OnTrafficDecision           govpn.TrafficPolicyCallback
}
