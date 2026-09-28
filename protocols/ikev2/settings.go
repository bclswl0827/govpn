package ikev2

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/bclswl0827/govpn/internal/netutil"
)

type clientSettings struct {
	ikeAddr, nattAddr  *net.UDPAddr
	localID, remoteID  identity
	psk                []byte
	username, password string
	ca                 *x509.CertPool
	serverName         string
	skipVerify         bool
	dhGroup            uint16
	mtu                int
	timeout            time.Duration
	logger             *log.Logger
	forceEncapsulation bool
}

func resolveClientSettings(config Config) (clientSettings, error) {
	if config.Server == "" {
		return clientSettings{}, errors.New("ikev2: server is required")
	}
	if config.LocalID == "" || config.RemoteID == "" {
		return clientSettings{}, errors.New("ikev2: LocalID and RemoteID are required")
	}
	passwordAuth := config.Username != "" || config.Password != ""
	if config.PSK != "" && passwordAuth {
		return clientSettings{}, errors.New("ikev2: PSK cannot be combined with Username or Password")
	}
	if config.PSK == "" && (config.Username == "" || config.Password == "") {
		return clientSettings{}, errors.New("ikev2: either PSK or both Username and Password are required")
	}
	localID, err := parseIdentity(config.LocalID)
	if err != nil {
		return clientSettings{}, fmt.Errorf("ikev2: local identity: %w", err)
	}
	remoteID, err := parseIdentity(config.RemoteID)
	if err != nil {
		return clientSettings{}, fmt.Errorf("ikev2: remote identity: %w", err)
	}
	ikePort := config.IKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	nattPort := config.NATTPort
	if nattPort == 0 {
		nattPort = defaultNATTPort
	}
	if !validPort(ikePort) || !validPort(nattPort) {
		return clientSettings{}, errors.New("ikev2: IKE and NAT-T ports must be between 1 and 65535")
	}
	ikeAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(config.Server, strconv.Itoa(ikePort)))
	if err != nil {
		return clientSettings{}, fmt.Errorf("ikev2: resolve server: %w", err)
	}
	nattAddr := &net.UDPAddr{IP: append(net.IP(nil), ikeAddr.IP...), Port: nattPort}
	mtu, err := resolveMTU(config.MTU)
	if err != nil {
		return clientSettings{}, err
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	var roots *x509.CertPool
	if len(config.CA) != 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(config.CA) {
			return clientSettings{}, errors.New("ikev2: CA contains no valid PEM certificates")
		}
	}
	serverName := config.ServerName
	if serverName == "" {
		switch remoteID.typeID {
		case idIPv4:
			serverName = net.IP(remoteID.data).String()
		case idFQDN:
			serverName = string(remoteID.data)
		}
	}
	if passwordAuth && !config.SkipVerify && serverName == "" {
		return clientSettings{}, errors.New("ikev2: ServerName is required when RemoteID is not an IPv4 or FQDN identity")
	}
	dhGroup := uint16(dhMODP2048)
	if config.AllowLegacyMODP1024 {
		dhGroup = dhMODP1024
	}
	return clientSettings{
		ikeAddr: ikeAddr, nattAddr: nattAddr, localID: localID, remoteID: remoteID,
		psk: []byte(config.PSK), username: config.Username, password: config.Password,
		ca: roots, serverName: serverName, skipVerify: config.SkipVerify, dhGroup: dhGroup,
		mtu: mtu, timeout: timeout, logger: logger,
		forceEncapsulation: !config.DisableForceEncapsulation,
	}, nil
}

type serverSettings struct {
	listenIP, publicIP  net.IP
	ikePort, nattPort   int
	identity            identity
	users               map[string][]byte
	passwordUsers       map[string]string
	certificates        []*x509.Certificate
	privateKey          *rsa.PrivateKey
	allowLegacyMODP1024 bool
	network             netip.Prefix
	gateway             netip.Addr
	dns                 []net.IP
	mtu                 int
	logger              *log.Logger
	forceEncapsulation  bool
}

func resolveServerSettings(config ServerConfig) (serverSettings, error) {
	listenText := config.ListenIP
	if listenText == "" {
		listenText = "0.0.0.0"
	}
	listenIP := net.ParseIP(listenText).To4()
	if listenIP == nil {
		return serverSettings{}, fmt.Errorf("ikev2: invalid IPv4 listen address %q", listenText)
	}
	publicText := config.PublicIP
	if publicText == "" && !listenIP.IsUnspecified() {
		publicText = listenText
	}
	if publicText == "" {
		return serverSettings{}, errors.New("ikev2: PublicIP is required when ListenIP is unspecified")
	}
	publicIP := net.ParseIP(publicText).To4()
	if publicIP == nil || publicIP.IsUnspecified() {
		return serverSettings{}, fmt.Errorf("ikev2: invalid concrete PublicIP %q", publicText)
	}
	if config.Identity == "" {
		return serverSettings{}, errors.New("ikev2: server Identity is required")
	}
	serverID, err := parseIdentity(config.Identity)
	if err != nil {
		return serverSettings{}, fmt.Errorf("ikev2: server identity: %w", err)
	}
	if len(config.Users) == 0 && len(config.PasswordUsers) == 0 {
		return serverSettings{}, errors.New("ikev2: at least one identity is required")
	}
	users := make(map[string][]byte, len(config.Users))
	for name, secret := range config.Users {
		if name == "" || secret == "" {
			return serverSettings{}, errors.New("ikev2: identities and pre-shared keys must not be empty")
		}
		id, err := parseIdentity(name)
		if err != nil {
			return serverSettings{}, fmt.Errorf("ikev2: identity %q: %w", name, err)
		}
		users[id.key()] = []byte(secret)
	}
	passwordUsers := make(map[string]string, len(config.PasswordUsers))
	for name, password := range config.PasswordUsers {
		if name == "" || password == "" {
			return serverSettings{}, errors.New("ikev2: EAP usernames and passwords must not be empty")
		}
		passwordUsers[name] = password
	}
	var certificates []*x509.Certificate
	var privateKey *rsa.PrivateKey
	if len(passwordUsers) != 0 {
		if len(config.Certificate) == 0 || len(config.PrivateKey) == 0 {
			return serverSettings{}, errors.New("ikev2: Certificate and PrivateKey are required for password authentication")
		}
		certificates, err = parseCertificates(config.Certificate)
		if err != nil {
			return serverSettings{}, fmt.Errorf("ikev2: responder certificate: %w", err)
		}
		privateKey, err = parseRSAPrivateKey(config.PrivateKey)
		if err != nil {
			return serverSettings{}, fmt.Errorf("ikev2: responder private key: %w", err)
		}
		publicKey, ok := certificates[0].PublicKey.(*rsa.PublicKey)
		if !ok || publicKey.E != privateKey.PublicKey.E || publicKey.N.Cmp(privateKey.PublicKey.N) != 0 {
			return serverSettings{}, errors.New("ikev2: responder certificate and private key do not match")
		}
	}
	ikePort := config.IKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	nattPort := config.NATTPort
	if nattPort == 0 {
		nattPort = defaultNATTPort
	}
	if !validPort(ikePort) || !validPort(nattPort) || ikePort == nattPort {
		return serverSettings{}, errors.New("ikev2: IKE and NAT-T ports must be valid and different")
	}
	poolText := config.Pool
	if poolText == "" {
		poolText = defaultPool
	}
	network, gateway, _, err := netutil.ParseIPv4Pool(poolText)
	if err != nil {
		return serverSettings{}, fmt.Errorf("ikev2: %w", err)
	}
	dns := make([]net.IP, 0, len(config.DNS))
	for _, address := range config.DNS {
		v4 := address.To4()
		if v4 == nil {
			return serverSettings{}, fmt.Errorf("ikev2: DNS address %q is not IPv4", address)
		}
		dns = append(dns, append(net.IP(nil), v4...))
	}
	mtu, err := resolveMTU(config.MTU)
	if err != nil {
		return serverSettings{}, err
	}
	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return serverSettings{
		listenIP: listenIP, publicIP: publicIP, ikePort: ikePort, nattPort: nattPort,
		identity: serverID, users: users, passwordUsers: passwordUsers,
		certificates: certificates, privateKey: privateKey,
		allowLegacyMODP1024: config.AllowLegacyMODP1024,
		network:             network, gateway: gateway,
		dns: dns, mtu: mtu, logger: logger,
		forceEncapsulation: !config.DisableForceEncapsulation,
	}, nil
}

func resolveMTU(value int) (int, error) {
	if value == 0 {
		value = defaultMTU
	}
	if value < 576 || value > defaultMTU {
		return 0, fmt.Errorf("ikev2: MTU must be between 576 and %d", defaultMTU)
	}
	return value, nil
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

func outboundIPv4(remote *net.UDPAddr) (net.IP, error) {
	probe, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return nil, fmt.Errorf("ikev2: route to %s: %w", remote.IP, err)
	}
	defer probe.Close()
	local, ok := probe.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil {
		return nil, errors.New("ikev2: cannot determine local IPv4 address")
	}
	return append(net.IP(nil), local.IP.To4()...), nil
}
