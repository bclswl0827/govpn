package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const minimumIPv6MTU = 1280

// Switch shortly before wireguard-go's native retry timer fires so the next
// handshake initiation is sent to the next endpoint candidate. Candidates are
// cycled until one completes a handshake.
const endpointFailoverDelay = device.RekeyTimeout - time.Second

func start(addresses []netip.Prefix, mtu int, uapi string, peers []Peer, logger *log.Logger, serverOptions *govpn.ServerSessionOptions) (*govpn.Session, *Runtime, error) {
	memory, err := packet.New("wireguard", mtu)
	if err != nil {
		return nil, nil, err
	}
	wg := device.NewDevice(memory, conn.NewDefaultBind(), wireGuardLogger(logger))
	transport := &Runtime{device: wg, logger: logger}
	if err := wg.IpcSet(uapi); err != nil {
		transport.Close()
		return nil, nil, fmt.Errorf("wireguard: configure device: %w", err)
	}
	if err := wg.Up(); err != nil {
		transport.Close()
		return nil, nil, fmt.Errorf("wireguard: bring device up: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		<-wg.Wait()
		done <- nil
	}()
	var session *govpn.Session
	if serverOptions == nil {
		session, err = govpn.NewSession(addresses, uint32(mtu), memory, transport.Close, done)
	} else {
		session, err = govpn.NewServerSession(addresses, uint32(mtu), memory, transport.Close, done, *serverOptions)
	}
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	transport.startEndpointFailover(peers)
	return session, transport, nil
}

type Runtime struct {
	device *device.Device
	logger *log.Logger
	once   sync.Once

	failoverMu     sync.Mutex
	failovers      []endpointFailoverState
	failoverCancel context.CancelFunc
	failoverWG     sync.WaitGroup
}

type endpointFailoverState struct {
	publicKey      string
	publicHex      string
	candidates     []string
	current        int
	lastTransmit   uint64
	attemptStarted time.Time
}

func (t *Runtime) Close() error {
	if t == nil || t.device == nil {
		return nil
	}
	t.once.Do(func() {
		if t.failoverCancel != nil {
			t.failoverCancel()
		}
		t.device.Close()
		t.failoverWG.Wait()
	})
	return nil
}

func (t *Runtime) UAPIGet() (string, error) {
	if t == nil || t.device == nil {
		return "", ErrNotStarted
	}
	return t.device.IpcGet()
}

func (t *Runtime) UAPISet(configuration string) error {
	if t == nil || t.device == nil {
		return ErrNotStarted
	}
	return t.device.IpcSet(configuration)
}

func (t *Runtime) Status() (Status, error) {
	configuration, err := t.UAPIGet()
	if err != nil {
		return Status{}, err
	}
	return parseStatus(configuration)
}

func (t *Runtime) ReplacePeers(ctx context.Context, peers []Peer) error {
	prepared, err := preparePeers(ctx, peers)
	if err != nil {
		return err
	}
	var configuration strings.Builder
	configuration.WriteString("replace_peers=true\n")
	if err := appendPeerConfiguration(&configuration, prepared); err != nil {
		return err
	}
	if err := t.UAPISet(configuration.String()); err != nil {
		return err
	}
	t.setEndpointFailovers(prepared)
	return nil
}

func (t *Runtime) UpdatePeer(ctx context.Context, update PeerUpdate) error {
	var configuration strings.Builder
	if err := appendPeerUpdate(ctx, &configuration, update); err != nil {
		return err
	}
	if err := t.UAPISet(configuration.String()); err != nil {
		return err
	}
	if update.Endpoint != nil {
		t.removeEndpointFailover(update.PublicKey)
	}
	return nil
}

func (t *Runtime) RemovePeer(publicKey string) error {
	publicHex, err := keyHex(publicKey, false)
	if err != nil {
		return fmt.Errorf("wireguard: peer public key: %w", err)
	}
	if err := t.UAPISet(fmt.Sprintf("public_key=%s\nremove=true\n", publicHex)); err != nil {
		return err
	}
	t.removeEndpointFailover(publicKey)
	return nil
}

func (t *Runtime) startEndpointFailover(peers []Peer) {
	ctx, cancel := context.WithCancel(context.Background())
	t.failoverCancel = cancel
	t.setEndpointFailovers(peers)
	t.failoverWG.Add(1)
	go t.runEndpointFailover(ctx)
}

func (t *Runtime) setEndpointFailovers(peers []Peer) {
	states := make([]endpointFailoverState, 0, len(peers))
	for _, peer := range peers {
		if len(peer.endpointCandidates) < 2 {
			continue
		}
		decoded, err := decodeKey(peer.PublicKey)
		if err != nil {
			continue
		}
		states = append(states, endpointFailoverState{
			publicKey:  base64.StdEncoding.EncodeToString(decoded),
			publicHex:  fmt.Sprintf("%x", decoded),
			candidates: append([]string(nil), peer.endpointCandidates...),
		})
	}
	t.failoverMu.Lock()
	t.failovers = states
	t.failoverMu.Unlock()
}

func (t *Runtime) removeEndpointFailover(publicKey string) {
	decoded, err := decodeKey(publicKey)
	if err != nil {
		return
	}
	canonical := base64.StdEncoding.EncodeToString(decoded)
	t.failoverMu.Lock()
	defer t.failoverMu.Unlock()
	for i := range t.failovers {
		if t.failovers[i].publicKey == canonical {
			t.failovers = append(t.failovers[:i], t.failovers[i+1:]...)
			return
		}
	}
}

func (t *Runtime) runEndpointFailover(ctx context.Context) {
	defer t.failoverWG.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t.checkEndpointFailover(now)
		}
	}
}

func (t *Runtime) checkEndpointFailover(now time.Time) {
	t.failoverMu.Lock()
	defer t.failoverMu.Unlock()
	if len(t.failovers) == 0 {
		return
	}
	status, err := t.Status()
	if err != nil {
		return
	}
	for i := 0; i < len(t.failovers); {
		state := &t.failovers[i]
		var peer *PeerStatus
		for j := range status.Peers {
			if status.Peers[j].PublicKey == state.publicKey {
				peer = &status.Peers[j]
				break
			}
		}
		if peer == nil || !peer.LastHandshake.IsZero() {
			t.failovers = append(t.failovers[:i], t.failovers[i+1:]...)
			continue
		}
		if state.attemptStarted.IsZero() {
			if peer.TransmitBytes <= state.lastTransmit {
				i++
				continue
			}
			state.lastTransmit = peer.TransmitBytes
			state.attemptStarted = now
			i++
			continue
		}
		if now.Sub(state.attemptStarted) < endpointFailoverDelay {
			i++
			continue
		}
		next := (state.current + 1) % len(state.candidates)
		endpoint := state.candidates[next]
		configuration := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", state.publicHex, endpoint)
		if err := t.UAPISet(configuration); err == nil {
			state.current = next
			state.lastTransmit = peer.TransmitBytes
			state.attemptStarted = time.Time{}
			if t.logger != nil {
				t.logger.Printf("[wireguard] handshake endpoint fallback: endpoint=%s", endpoint)
			}
		} else {
			state.attemptStarted = now
		}
		i++
	}
}

func (t *Runtime) SetPrivateKey(privateKey string) error {
	privateHex, err := keyHex(privateKey, false)
	if err != nil {
		return fmt.Errorf("wireguard: private key: %w", err)
	}
	return t.UAPISet("private_key=" + privateHex + "\n")
}

func (t *Runtime) ClearPrivateKey() error {
	return t.UAPISet("private_key=" + strings.Repeat("0", 64) + "\n")
}

func (t *Runtime) SetListenPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("wireguard: listen port %d is out of range", port)
	}
	return t.UAPISet(fmt.Sprintf("listen_port=%d\n", port))
}

func (t *Runtime) SetFirewallMark(mark uint32) error {
	return t.UAPISet(fmt.Sprintf("fwmark=%d\n", mark))
}

func wireGuardLogger(logger *log.Logger) *device.Logger {
	if logger == nil {
		return device.NewLogger(device.LogLevelSilent, "")
	}
	return &device.Logger{Verbosef: logger.Printf, Errorf: logger.Printf}
}

func normalizedMTU(mtu int) int {
	if mtu == 0 {
		return defaultMTU
	}
	if mtu < 576 || mtu > 65535 {
		return 0
	}
	return mtu
}

func validateAddressMTU(addresses []netip.Prefix, mtu int) error {
	if mtu >= minimumIPv6MTU {
		return nil
	}
	for _, address := range addresses {
		if address.Addr().Is6() {
			return fmt.Errorf("wireguard: IPv6 requires an MTU of at least %d, got %d", minimumIPv6MTU, mtu)
		}
	}
	return nil
}

func parseAddresses(values []string) ([]netip.Prefix, error) {
	addresses := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("wireguard: address %q: %w", value, err)
		}
		addresses = append(addresses, prefix)
	}
	return addresses, nil
}
