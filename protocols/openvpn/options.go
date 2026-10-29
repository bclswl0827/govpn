package openvpn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/go-lzo"
	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

func clientOptions(config Config) string {
	cipherName := effectiveCipher(config)
	auth := effectiveAuth(config)
	keySize := cipherKeySize(cipherName)
	mtu := config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	options := fmt.Sprintf("V4,dev-type tun,link-mtu %d,tun-mtu %d,proto %s,cipher %s,auth %s,keysize %d,key-method 2,tls-client", mtu+49, mtu, clientProtocolOption(config), cipherName, auth, keySize)
	if strings.EqualFold(config.Compression, "lzo") {
		options += ",comp-lzo"
	}
	return options
}

func effectiveCipher(config Config) string {
	if config.Cipher != "" {
		return normalizeCipherName(config.Cipher)
	}
	if len(config.DataCiphers) != 0 {
		return config.DataCiphers[0]
	}
	return "AES-256-GCM"
}

func effectiveAuth(config Config) string {
	if config.Auth != "" {
		return config.Auth
	}
	if strings.HasSuffix(strings.ToUpper(effectiveCipher(config)), "-CBC") {
		return "SHA1"
	}
	return "SHA256"
}

func effectiveCompression(config Config) string {
	if config.Compression == "" {
		return "none"
	}
	return config.Compression
}

func effectiveMTU(mtu int) int {
	if mtu == 0 {
		return defaultMTU
	}
	return mtu
}

func clientPeerInfo(config Config) string {
	// Advertise only capabilities implemented by this client. In particular,
	// advertising dynamic tls-crypt makes servers select a rekey mode that the
	// control channel cannot currently process.
	const ivProto = 1<<1 | 1<<3 // P_DATA_V2 and TLS key material export.
	peerInfo := fmt.Sprintf("IV_VER=2.6.0\nIV_PROTO=%d\nIV_NCP=2\nIV_CIPHERS=%s\n", ivProto, strings.Join(effectiveClientDataCiphers(config), ":"))
	if strings.EqualFold(config.Compression, "lzo") {
		peerInfo += "IV_LZO=1\n"
	}
	return peerInfo
}

func newClientDataCipher(config Config, key protocol.KeyPair) (dataCipher, error) {
	return newDataCipher(effectiveCipher(config), effectiveAuth(config), key)
}

func newDataCipher(cipherName, auth string, key protocol.KeyPair) (dataCipher, error) {
	if strings.HasSuffix(strings.ToUpper(cipherName), "-CBC") {
		return protocol.NewCBCDataCipher(key, cipherName, auth)
	}
	return protocol.NewAEADDataCipher(key, cipherName)
}

func transportNetwork(config Config) string {
	if config.Protocol == "" {
		return "udp"
	}
	return strings.ToLower(config.Protocol)
}

func clientProtocolOption(config Config) string {
	network := transportNetwork(config)
	if strings.HasPrefix(network, "tcp") {
		if network == "tcp6" {
			return "TCPv6_CLIENT"
		}
		return "TCPv4_CLIENT"
	}
	if network == "udp6" {
		return "UDPv6_CLIENT"
	}
	return "UDPv4_CLIENT"
}

func compressPacket(packet []byte, compression string) ([]byte, error) {
	if compression == "" {
		return packet, nil
	}
	if strings.EqualFold(compression, "lzo") {
		return append([]byte{0xfa}, packet...), nil
	}
	return nil, errors.New("openvpn: unsupported compression")
}

// packetDecompressor belongs to one receive loop. Compressed output is valid
// until the next call and must be copied before it is queued for another reader.
type packetDecompressor struct {
	compression string
	buffer      []byte
}

func (d *packetDecompressor) decompress(packet []byte) ([]byte, error) {
	if d.compression == "" {
		return packet, nil
	}
	if len(packet) == 0 {
		return nil, errors.New("openvpn: empty compressed packet")
	}
	switch packet[0] {
	case 0xfa:
		return packet[1:], nil
	case 0x66:
		// An IPv4 or IPv6 packet cannot exceed 65,535 bytes. Keeping a fixed
		// output bound also prevents a malformed compressed packet from causing
		// unbounded allocation.
		if d.buffer == nil {
			d.buffer = make([]byte, 65535)
		}
		length, err := lzo.Decompress(packet[1:], d.buffer)
		if err != nil {
			return nil, fmt.Errorf("openvpn: decompress LZO payload: %w", err)
		}
		return d.buffer[:length], nil
	default:
		return nil, fmt.Errorf("openvpn: invalid compression marker 0x%02x", packet[0])
	}
}

func serverOptions(config ServerConfig, cipherName string) string {
	mtu := effectiveMTU(config.MTU)
	keySize := cipherKeySize(cipherName)
	proto := "UDPv4_SERVER"
	network := strings.ToLower(config.Protocol)
	if strings.HasPrefix(network, "tcp") {
		proto = "TCPv4_SERVER"
		if network == "tcp6" {
			proto = "TCPv6_SERVER"
		}
	} else if network == "udp6" {
		proto = "UDPv6_SERVER"
	}
	return fmt.Sprintf("V4,dev-type tun,link-mtu %d,tun-mtu %d,proto %s,cipher %s,auth %s,keysize %d,key-method 2,tls-server", mtu+49, mtu, proto, cipherName, effectiveServerAuth(config), keySize)
}

func cipherKeySize(name string) int {
	switch normalizeCipherName(name) {
	case "AES-128-GCM", "AES-128-CBC", "BF-CBC":
		return 128
	case "AES-192-GCM", "AES-192-CBC":
		return 192
	default:
		return 256
	}
}

func effectiveServerAuth(config ServerConfig) string {
	if config.Auth != "" {
		return config.Auth
	}
	return "SHA256"
}

type pushedOptions struct {
	address      netip.Addr
	prefixBits   int
	address6     netip.Addr
	prefixBits6  int
	cipher       string
	peerID       uint32
	usePeerID    bool
	tlsEKM       bool
	pingInterval time.Duration
	pingTimeout  time.Duration
}

func parsePushReply(reply string) (netip.Addr, int, error) {
	options, err := parsePushOptions(reply)
	return options.address, options.prefixBits, err
}

func parsePushOptions(reply string) (pushedOptions, error) {
	if !strings.HasPrefix(reply, "PUSH_REPLY,") {
		return pushedOptions{}, errors.New("openvpn: invalid PUSH_REPLY")
	}
	var result pushedOptions
	hasAddress := false
	for _, option := range strings.Split(strings.TrimPrefix(reply, "PUSH_REPLY,"), ",") {
		fields := strings.Fields(option)
		if len(fields) == 3 && fields[0] == "ifconfig" {
			address, err := netip.ParseAddr(fields[1])
			if err != nil || !address.Is4() {
				continue
			}
			result.address = address
			if maskIP := net.ParseIP(fields[2]).To4(); maskIP != nil {
				bits, total := net.IPMask(maskIP).Size()
				if bits >= 0 && total == 32 {
					result.prefixBits = bits
					hasAddress = true
					continue
				}
			}
			peer, peerErr := netip.ParseAddr(fields[2])
			if peerErr == nil && peer.Is4() {
				result.prefixBits = 32
				hasAddress = true
			}
			continue
		}
		if len(fields) == 3 && fields[0] == "ifconfig-ipv6" {
			prefix, err := netip.ParsePrefix(fields[1])
			if err != nil || !prefix.Addr().Is6() {
				continue
			}
			result.address6 = prefix.Addr()
			result.prefixBits6 = prefix.Bits()
			hasAddress = true
			continue
		}
		if len(fields) == 2 && (fields[0] == "ping" || fields[0] == "ping-restart" || fields[0] == "ping-exit") {
			seconds, err := strconv.Atoi(fields[1])
			if err != nil || seconds < 0 || seconds > 86400 {
				return pushedOptions{}, fmt.Errorf("openvpn: invalid PUSH_REPLY %s value", fields[0])
			}
			duration := time.Duration(seconds) * time.Second
			if fields[0] == "ping" {
				result.pingInterval = duration
			} else {
				result.pingTimeout = duration
			}
		}
		if len(fields) == 2 && fields[0] == "cipher" {
			if !supportedDataCipher(fields[1]) {
				return pushedOptions{}, fmt.Errorf("openvpn: server selected unsupported cipher %q", fields[1])
			}
			result.cipher = normalizeCipherName(fields[1])
		}
		if len(fields) == 2 && fields[0] == "peer-id" {
			peerID, err := strconv.ParseUint(fields[1], 10, 24)
			if err != nil {
				return pushedOptions{}, errors.New("openvpn: invalid PUSH_REPLY peer-id value")
			}
			result.peerID = uint32(peerID)
			result.usePeerID = true
		}
		if len(fields) >= 2 && fields[0] == "protocol-flags" {
			for _, flag := range fields[1:] {
				result.tlsEKM = result.tlsEKM || flag == "tls-ekm"
			}
		}
		if len(fields) == 2 && fields[0] == "key-derivation" {
			result.tlsEKM = result.tlsEKM || fields[1] == "tls-ekm"
		}
	}
	if !hasAddress {
		return pushedOptions{}, errors.New("openvpn: PUSH_REPLY has no valid tunnel address")
	}
	return result, nil
}
