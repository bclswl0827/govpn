package openvpn

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	config := c.Config
	if err := validateClient(config); err != nil {
		return nil, err
	}
	c.logf("starting client: remotes=%d cipher-list=%s auth=%s compression=%s mtu=%d", len(clientRemotes(config)), strings.Join(effectiveClientDataCiphers(config), ":"), effectiveAuth(config), effectiveCompression(config), effectiveMTU(config.MTU))
	var certificate *tls.Certificate
	if len(config.Cert) != 0 || len(config.Key) != 0 {
		parsed, err := tls.X509KeyPair(config.Cert, config.Key)
		if err != nil {
			return nil, fmt.Errorf("openvpn: client certificate: %w", err)
		}
		certificate = &parsed
	}
	tlsConfig, err := clientTLSConfig(config, certificate)
	if err != nil {
		return nil, err
	}
	c.logf("configuration validated: client-certificate=%t username-password=%t", certificate != nil, config.Username != "" || config.Password != "")
	dialer := net.Dialer{}
	var rawConn net.Conn
	var network string
	var dialErr error
	for _, remote := range clientRemotes(config) {
		candidate := config
		candidate.Remote, candidate.Port = remote.Host, remote.Port
		if remote.Protocol != "" {
			candidate.Protocol = remote.Protocol
		}
		network = transportNetwork(candidate)
		address := net.JoinHostPort(candidate.Remote, strconv.Itoa(candidate.Port))
		c.logf("connecting transport: remote=%s protocol=%s", address, network)
		rawConn, dialErr = dialer.DialContext(ctx, network, address)
		if dialErr == nil {
			config = candidate
			break
		}
		c.logf("transport connection failed: remote=%s error=%v", address, dialErr)
	}
	if rawConn == nil {
		return nil, fmt.Errorf("openvpn: all remote connections failed: %w", dialErr)
	}
	conn := rawConn
	if strings.HasPrefix(network, "tcp") {
		conn = protocol.NewStreamConn(rawConn)
	}
	protectedConn, err := protectClientControl(conn, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = protectedConn
	c.logf("%s transport connected: local=%s remote=%s", network, conn.LocalAddr(), conn.RemoteAddr())
	setHandshakeDeadline(ctx, conn)
	endpoint, err := protocol.ClientEndpoint(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.logf("OpenVPN control channel established")
	control := protocol.NewControlConn(endpoint)
	tlsConn := tls.Client(control, tlsConfig)
	c.logf("starting TLS handshake")
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = endpoint.Close()
		return nil, fmt.Errorf("openvpn: TLS handshake: %w", err)
	}
	tlsState := tlsConn.ConnectionState()
	c.logf("TLS handshake completed: version=0x%04x cipher-suite=0x%04x", tlsState.Version, tlsState.CipherSuite)
	setHandshakeDeadline(ctx, conn)
	clientSource, err := protocol.NewClientKeySource()
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	options := clientOptions(config)
	c.logf("sending key-method authentication")
	if err := protocol.WriteKeyMethod(tlsConn, protocol.KeyMethodMessage{
		Source: clientSource, Options: options, Username: config.Username,
		Password: config.Password, PeerInfo: clientPeerInfo(config),
	}, false); err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	reader := bufio.NewReader(tlsConn)
	serverMessage, err := protocol.ReadKeyMethod(reader, false)
	if err != nil {
		_ = endpoint.Close()
		return nil, fmt.Errorf("openvpn: key-method response: %w", err)
	}
	c.logf("key-method response received")
	c.logf("requesting tunnel parameters")
	if err := protocol.WriteCommand(tlsConn, "PUSH_REQUEST"); err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	pushReply, err := readPushReply(reader)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	pushed, err := parsePushOptions(pushReply)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	if pushed.cipher == "" {
		// A non-NCP server does not push a cipher. In that case OpenVPN
		// continues using the legacy cipher from the key-method options.
		pushed.cipher = effectiveCipher(config)
	}
	allowedCipher := false
	for _, name := range effectiveClientDataCiphers(config) {
		allowedCipher = allowedCipher || normalizeCipherName(name) == pushed.cipher
	}
	if !allowedCipher && normalizeCipherName(config.DataCipherFallback) != pushed.cipher {
		_ = endpoint.Close()
		return nil, fmt.Errorf("openvpn: server selected cipher %s outside data-ciphers", pushed.cipher)
	}
	keyDerivation := "openvpn-prf"
	var keys protocol.DataKeys
	if pushed.tlsEKM {
		keyDerivation = "tls-ekm"
		keys, err = protocol.ExportDataKeys(&tlsState)
	} else {
		keys = protocol.DeriveKeys(clientSource, serverMessage.Source, endpoint.LocalSessionID(), endpoint.RemoteSessionID())
	}
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	c.logf("tunnel parameters received: address=%s/%d address6=%s/%d cipher=%s peer-id=%d data-v2=%t key-derivation=%s ping=%s receive-timeout=%s", pushed.address, pushed.prefixBits, pushed.address6, pushed.prefixBits6, pushed.cipher, pushed.peerID, pushed.usePeerID, keyDerivation, pushed.pingInterval, pushed.pingTimeout)
	sendCipher, err := newDataCipher(pushed.cipher, effectiveAuth(config), keys.Client)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	receiveCipher, err := newDataCipher(pushed.cipher, effectiveAuth(config), keys.Server)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	mtu := config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	device, err := packet.New("openvpn-client", mtu)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	// The connection deadline only bounds control-channel negotiation. Leaving
	// it armed makes a healthy data channel fail when the handshake timeout
	// expires, even if packets and keepalives are flowing normally.
	deadlineErr := errors.Join(rawConn.SetReadDeadline(time.Time{}), rawConn.SetWriteDeadline(time.Time{}))
	if deadlineErr != nil {
		_ = endpoint.Close()
		_ = device.Close()
		return nil, fmt.Errorf("openvpn: clear handshake deadline: %w", deadlineErr)
	}
	c.logf("handshake deadline cleared: transport=%s", network)
	transport := newTransport(endpoint, device, sendCipher, receiveCipher, pushed.usePeerID, pushed.peerID, config.Compression, pushed.pingInterval, pushed.pingTimeout, config.Logger)
	// Keep consuming TLS records and commands after PUSH_REPLY. Otherwise the
	// endpoint's control queue eventually blocks the shared packet read loop.
	transport.controlReader = reader
	done := make(chan error, 1)
	go transport.run(done)
	addresses := make([]netip.Prefix, 0, 2)
	if pushed.address.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(pushed.address, pushed.prefixBits))
	}
	if pushed.address6.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(pushed.address6, pushed.prefixBits6))
	}
	session, err := govpn.NewSession(addresses, uint32(mtu), device, transport.Close, done)
	if err != nil {
		return nil, err
	}
	c.logf("data channel ready")
	return session, nil
}

func readPushReply(reader *bufio.Reader) (string, error) {
	const maxControlMessages = 64
	for range maxControlMessages {
		command, err := protocol.ReadCommand(reader, 16384)
		if err != nil {
			return "", fmt.Errorf("openvpn: read PUSH_REPLY: %w", err)
		}
		switch {
		case command == "PUSH_REPLY" || strings.HasPrefix(command, "PUSH_REPLY,"):
			return command, nil
		case command == "INFO" || strings.HasPrefix(command, "INFO,"),
			command == "INFO_PRE" || strings.HasPrefix(command, "INFO_PRE,"),
			command == "ECHO" || strings.HasPrefix(command, "ECHO,"),
			command == "AUTH_PENDING" || strings.HasPrefix(command, "AUTH_PENDING,"):
			continue
		case command == "AUTH_FAILED" || strings.HasPrefix(command, "AUTH_FAILED,"):
			return "", fmt.Errorf("openvpn: authentication failed: %s", command)
		case command == "RESTART" || strings.HasPrefix(command, "RESTART,"),
			command == "HALT" || strings.HasPrefix(command, "HALT,"):
			return "", fmt.Errorf("openvpn: server rejected the session: %s", command)
		default:
			return "", fmt.Errorf("openvpn: unexpected control command while waiting for PUSH_REPLY: %q", command)
		}
	}
	return "", errors.New("openvpn: too many control messages while waiting for PUSH_REPLY")
}

func clientRemotes(config Config) []Remote {
	if len(config.Remotes) != 0 {
		return append([]Remote(nil), config.Remotes...)
	}
	return []Remote{{Host: config.Remote, Port: config.Port, Protocol: config.Protocol}}
}

func (c *Client) logf(format string, arguments ...any) {
	if c.Config.Logger != nil {
		c.Config.Logger.Printf("[openvpn] "+format, arguments...)
	}
}
