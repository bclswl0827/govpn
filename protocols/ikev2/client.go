package ikev2

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

func (client *Client) Start(ctx context.Context) (*govpn.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, err := resolveClientSettings(client.Config)
	if err != nil {
		return nil, err
	}
	localIP, err := outboundIPv4(settings.ikeAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, fmt.Errorf("ikev2: bind UDP: %w", err)
	}
	device, err := packet.New("ikev2-client", settings.mtu)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	transport := &clientTransport{
		settings: settings, conn: conn, device: device, localIP: localIP,
		done: make(chan error, 1),
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = transport.Close()
			_ = device.Close()
		}
	}()

	handshakeContext, cancel := context.WithTimeout(ctx, settings.timeout)
	defer cancel()
	address, prefixBits, err := transport.handshake(handshakeContext)
	if err != nil {
		return nil, fmt.Errorf("ikev2: handshake: %w", err)
	}
	transport.start()
	assigned, ok := netip.AddrFromSlice(address)
	if !ok {
		return nil, errors.New("ikev2: responder assigned an invalid IPv4 address")
	}
	closeTransport := func() error { return transport.Close() }
	session, err := govpn.NewSession(
		[]netip.Prefix{netip.PrefixFrom(assigned.Unmap(), prefixBits)},
		uint32(settings.mtu), device, closeTransport, transport.done,
	)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	settings.logger.Printf("[ikev2] tunnel established: address=%s/%d", assigned, prefixBits)
	return session, nil
}

type clientTransport struct {
	settings clientSettings
	conn     *net.UDPConn
	device   *packet.Device
	localIP  net.IP

	initiatorSPI, responderSPI uint64
	ni, nr                     []byte
	keys                       ikeKeys
	esp                        *espSA
	natt                       bool
	assigned                   net.IP
	remoteSelectors            [][2]net.IP

	runContext context.Context
	cancelRun  context.CancelFunc
	done       chan error
	closeOnce  sync.Once
	failOnce   sync.Once
	writeMu    sync.Mutex
}

func (client *clientTransport) handshake(ctx context.Context) (net.IP, int, error) {
	spi, err := randomUint64()
	if err != nil {
		return nil, 0, err
	}
	client.initiatorSPI = spi
	dh, public, err := generateMODPKey(client.settings.dhGroup)
	if err != nil {
		return nil, 0, err
	}
	client.ni, err = randomBytes(32)
	if err != nil {
		return nil, 0, err
	}
	localPort := client.conn.LocalAddr().(*net.UDPAddr).Port
	natSourcePort := localPort
	if client.settings.forceEncapsulation {
		natSourcePort = 0
	}
	header := ikeHeader{
		initiatorSPI: spi, exchange: exchangeIKEInit, flags: flagInitiator,
	}
	message1, err := marshalMessage(header, []payload{
		ikeProposal(client.settings.dhGroup), keyExchangePayload(client.settings.dhGroup, public), {typeID: payloadNonce, data: client.ni},
		notifyPayload(notifyNATSource, natDetectionHash(spi, 0, client.localIP, natSourcePort)),
		notifyPayload(notifyNATDestination, natDetectionHash(spi, 0, client.settings.ikeAddr.IP, client.settings.ikeAddr.Port)),
	})
	if err != nil {
		return nil, 0, err
	}
	message2, from, err := client.exchange(ctx, message1, client.settings.ikeAddr, false, exchangeIKEInit, 0)
	if err != nil {
		return nil, 0, err
	}
	header2, err := parseIKEHeader(message2)
	if err != nil {
		return nil, 0, err
	}
	if header2.initiatorSPI != spi || header2.responderSPI == 0 || header2.flags&flagResponse == 0 {
		return nil, 0, errors.New("invalid IKE_SA_INIT response header")
	}
	client.responderSPI = header2.responderSPI
	payloads2, err := parseMessagePayloads(message2, header2)
	if err != nil {
		return nil, 0, err
	}
	if err := notifyError(payloads2); err != nil {
		return nil, 0, err
	}
	sa, ok := firstPayload(payloads2, payloadSA)
	if !ok {
		return nil, 0, errors.New("IKE_SA_INIT response omitted SA")
	}
	if _, ok := selectProposal(sa.data, protocolIKE, client.settings.dhGroup); !ok {
		return nil, 0, errors.New("responder selected an unsupported IKE proposal")
	}
	ke, ok := firstPayload(payloads2, payloadKE)
	if !ok {
		return nil, 0, errors.New("IKE_SA_INIT response omitted KE")
	}
	peerPublic, err := parseKeyExchange(ke.data, client.settings.dhGroup)
	if err != nil {
		return nil, 0, err
	}
	nonce, ok := firstPayload(payloads2, payloadNonce)
	if !ok || len(nonce.data) < 16 {
		return nil, 0, errors.New("IKE_SA_INIT response has no valid nonce")
	}
	client.nr = append([]byte(nil), nonce.data...)
	shared, err := dh.secret(peerPublic)
	if err != nil {
		return nil, 0, err
	}
	client.keys = deriveIKEKeys(client.ni, client.nr, shared, client.initiatorSPI, client.responderSPI)
	expectedSource := natDetectionHash(client.initiatorSPI, client.responderSPI, from.IP, from.Port)
	expectedDestination := natDetectionHash(client.initiatorSPI, client.responderSPI, client.localIP, localPort)
	client.natt = client.settings.forceEncapsulation || detectsNAT(payloads2, expectedSource, expectedDestination)
	remote := client.settings.ikeAddr
	if client.natt {
		remote = client.settings.nattAddr
	}
	if client.settings.username != "" {
		return client.handshakeEAP(ctx, message1, message2, remote)
	}

	clientSPI, err := randomUint32()
	if err != nil {
		return nil, 0, err
	}
	idBody := client.settings.localID.body()
	auth := authenticationValue(client.settings.psk, message1, client.nr, client.keys.skPI, idBody)
	allStart, allEnd := net.IPv4zero, net.IPv4bcast
	inner := []payload{
		{typeID: payloadIDi, data: idBody}, authPayload(auth),
		configPayload(cfgRequest,
			configAttribute{typeID: cfgIPv4},
			configAttribute{typeID: cfgNetmask},
			configAttribute{typeID: cfgDNS},
		),
		espProposal(clientSPI),
		trafficSelectorPayload(payloadTSi, allStart, allEnd),
		trafficSelectorPayload(payloadTSr, allStart, allEnd),
	}
	header3 := ikeHeader{
		initiatorSPI: client.initiatorSPI, responderSPI: client.responderSPI,
		exchange: exchangeIKEAuth, flags: flagInitiator, messageID: 1,
	}
	message3, err := encryptMessage(header3, inner, client.keys, true)
	if err != nil {
		return nil, 0, err
	}
	message4, _, err := client.exchange(ctx, message3, remote, client.natt, exchangeIKEAuth, 1)
	if err != nil {
		return nil, 0, err
	}
	header4, inner4, err := decryptMessage(message4, client.keys, false)
	if err != nil {
		return nil, 0, err
	}
	if header4.initiatorSPI != client.initiatorSPI || header4.responderSPI != client.responderSPI ||
		header4.exchange != exchangeIKEAuth || header4.messageID != 1 || header4.flags&flagResponse == 0 {
		return nil, 0, errors.New("invalid IKE_AUTH response header")
	}
	if err := notifyError(inner4); err != nil {
		return nil, 0, err
	}
	idPayload, ok := firstPayload(inner4, payloadIDr)
	if !ok {
		return nil, 0, errors.New("IKE_AUTH response omitted IDr")
	}
	remoteID, err := decodeIdentity(idPayload.data)
	if err != nil || !remoteID.equal(client.settings.remoteID) {
		return nil, 0, errors.New("responder identity does not match RemoteID")
	}
	authPayloadValue, ok := firstPayload(inner4, payloadAUTH)
	if !ok {
		return nil, 0, errors.New("IKE_AUTH response omitted AUTH")
	}
	receivedAuth, err := parseAuth(authPayloadValue.data)
	if err != nil {
		return nil, 0, err
	}
	expectedAuth := authenticationValue(client.settings.psk, message2, client.ni, client.keys.skPR, idPayload.data)
	if !secretEqual(receivedAuth, expectedAuth) {
		return nil, 0, errors.New("responder authentication failed")
	}
	return client.completeChild(inner4, clientSPI)
}

func (client *clientTransport) handshakeEAP(ctx context.Context, message1, message2 []byte, remote *net.UDPAddr) (net.IP, int, error) {
	clientSPI, err := randomUint32()
	if err != nil {
		return nil, 0, err
	}
	idBody := client.settings.localID.body()
	allStart, allEnd := net.IPv4zero, net.IPv4bcast
	inner := []payload{
		{typeID: payloadIDi, data: idBody},
		configPayload(cfgRequest,
			configAttribute{typeID: cfgIPv4},
			configAttribute{typeID: cfgNetmask},
			configAttribute{typeID: cfgDNS},
		),
		espProposal(clientSPI),
		trafficSelectorPayload(payloadTSi, allStart, allEnd),
		trafficSelectorPayload(payloadTSr, allStart, allEnd),
	}
	messageID := uint32(1)
	_, responseInner, err := client.exchangeAuth(ctx, remote, messageID, inner)
	if err != nil {
		return nil, 0, err
	}
	if err := notifyError(responseInner); err != nil {
		return nil, 0, err
	}
	serverID, err := client.authenticateEAPResponder(responseInner, message2)
	if err != nil {
		return nil, 0, err
	}
	eapItem, ok := firstPayload(responseInner, payloadEAP)
	if !ok {
		return nil, 0, errors.New("IKE_AUTH response omitted EAP request")
	}
	state := eapClientState{username: client.settings.username, password: client.settings.password}
	eapValue := eapItem.data
	eapComplete := false
	for rounds := 0; rounds < 16; rounds++ {
		reply, complete, err := state.handle(eapValue)
		if err != nil {
			return nil, 0, err
		}
		if complete {
			eapComplete = true
			break
		}
		messageID++
		_, responseInner, err = client.exchangeAuth(ctx, remote, messageID, []payload{eapPayload(reply)})
		if err != nil {
			return nil, 0, err
		}
		if err := notifyError(responseInner); err != nil {
			return nil, 0, err
		}
		eapItem, ok = firstPayload(responseInner, payloadEAP)
		if !ok {
			return nil, 0, errors.New("IKE_AUTH response omitted the next EAP packet")
		}
		eapValue = eapItem.data
	}
	if !eapComplete || len(state.msk) != 64 {
		return nil, 0, errors.New("EAP exchange did not complete within sixteen IKE_AUTH rounds")
	}

	messageID++
	initiatorAuth := authenticationValue(state.msk, message1, client.nr, client.keys.skPI, idBody)
	_, finalInner, err := client.exchangeAuth(ctx, remote, messageID, []payload{authPayload(initiatorAuth)})
	if err != nil {
		return nil, 0, err
	}
	if err := notifyError(finalInner); err != nil {
		return nil, 0, err
	}
	authItem, ok := firstPayload(finalInner, payloadAUTH)
	if !ok {
		return nil, 0, errors.New("final IKE_AUTH response omitted AUTH")
	}
	responderAuth, err := parseAuth(authItem.data)
	if err != nil {
		return nil, 0, err
	}
	expected := authenticationValue(state.msk, message2, client.ni, client.keys.skPR, serverID)
	if !secretEqual(responderAuth, expected) {
		return nil, 0, errors.New("final EAP responder authentication failed")
	}
	return client.completeChild(finalInner, clientSPI)
}

func (client *clientTransport) exchangeAuth(ctx context.Context, remote *net.UDPAddr, messageID uint32, inner []payload) ([]byte, []payload, error) {
	request, err := encryptMessage(ikeHeader{
		initiatorSPI: client.initiatorSPI, responderSPI: client.responderSPI,
		exchange: exchangeIKEAuth, flags: flagInitiator, messageID: messageID,
	}, inner, client.keys, true)
	if err != nil {
		return nil, nil, err
	}
	response, _, err := client.exchange(ctx, request, remote, client.natt, exchangeIKEAuth, messageID)
	if err != nil {
		return nil, nil, err
	}
	header, decoded, err := decryptMessage(response, client.keys, false)
	if err != nil {
		return nil, nil, err
	}
	if header.initiatorSPI != client.initiatorSPI || header.responderSPI != client.responderSPI ||
		header.exchange != exchangeIKEAuth || header.messageID != messageID || header.flags&flagResponse == 0 {
		return nil, nil, errors.New("invalid IKE_AUTH response header")
	}
	return response, decoded, nil
}

func (client *clientTransport) authenticateEAPResponder(inner []payload, message2 []byte) ([]byte, error) {
	idPayload, ok := firstPayload(inner, payloadIDr)
	if !ok {
		return nil, errors.New("EAP IKE_AUTH response omitted IDr")
	}
	remoteID, err := decodeIdentity(idPayload.data)
	if err != nil || !remoteID.equal(client.settings.remoteID) {
		return nil, errors.New("responder identity does not match RemoteID")
	}
	certificates, err := certificatesFromPayloads(inner)
	if err != nil {
		return nil, err
	}
	if !client.settings.skipVerify {
		if err := verifyCertificateChain(certificates, client.settings.ca, client.settings.serverName); err != nil {
			return nil, err
		}
	}
	authItem, ok := firstPayload(inner, payloadAUTH)
	if !ok {
		return nil, errors.New("EAP IKE_AUTH response omitted responder AUTH")
	}
	signature, err := parseRSAAuth(authItem.data)
	if err != nil {
		return nil, err
	}
	signed := signedOctets(message2, client.ni, client.keys.skPR, idPayload.data)
	if err := verifyRSAAuthentication(certificates[0], signed, signature); err != nil {
		return nil, err
	}
	return append([]byte(nil), idPayload.data...), nil
}

func (client *clientTransport) completeChild(inner []payload, clientSPI uint32) (net.IP, int, error) {
	childSA, ok := firstPayload(inner, payloadSA)
	if !ok {
		return nil, 0, errors.New("IKE_AUTH response omitted Child SA")
	}
	serverSPIBytes, ok := selectProposal(childSA.data, protocolESP)
	if !ok || len(serverSPIBytes) != 4 {
		return nil, 0, errors.New("responder selected an unsupported ESP proposal")
	}
	serverSPI := binary.BigEndian.Uint32(serverSPIBytes)
	cp, ok := firstPayload(inner, payloadCP)
	if !ok {
		return nil, 0, errors.New("IKE_AUTH response omitted address configuration")
	}
	assigned, prefixBits, err := parseAssignedIPv4(cp.data)
	if err != nil {
		return nil, 0, err
	}
	selectedTSi, ok := firstPayload(inner, payloadTSi)
	if !ok {
		return nil, 0, errors.New("IKE_AUTH response omitted TSi")
	}
	selectors, err := parseIPv4Selectors(selectedTSi.data)
	if err != nil || !selectorsContain(selectors, assigned) {
		return nil, 0, errors.New("responder traffic selectors exclude the assigned address")
	}
	selectedTSr, ok := firstPayload(inner, payloadTSr)
	if !ok {
		return nil, 0, errors.New("IKE_AUTH response omitted TSr")
	}
	remoteSelectors, err := parseIPv4Selectors(selectedTSr.data)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid responder traffic selector: %w", err)
	}
	client.assigned = assigned
	client.remoteSelectors = remoteSelectors
	material := deriveESPKeys(client.keys, client.ni, client.nr)
	client.esp = newInitiatorESP(serverSPI, clientSPI, material)
	_ = client.conn.SetReadDeadline(time.Time{})
	return assigned, prefixBits, nil
}

func (client *clientTransport) exchange(ctx context.Context, request []byte, remote *net.UDPAddr, natt bool, exchange uint8, messageID uint32) ([]byte, *net.UDPAddr, error) {
	delay := 500 * time.Millisecond
	buffer := make([]byte, 65535)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := client.send(request, remote, natt); err != nil {
			return nil, nil, err
		}
		deadline := time.Now().Add(delay)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		_ = client.conn.SetReadDeadline(deadline)
		for {
			n, from, err := client.conn.ReadFromUDP(buffer)
			if err != nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					break
				}
				return nil, nil, err
			}
			if !from.IP.Equal(remote.IP) {
				continue
			}
			packet := append([]byte(nil), buffer[:n]...)
			if natt && len(packet) >= 4 && binary.BigEndian.Uint32(packet[:4]) == 0 {
				packet = packet[4:]
			}
			header, err := parseIKEHeader(packet)
			if err != nil || header.exchange != exchange || header.messageID != messageID || header.flags&flagResponse == 0 {
				continue
			}
			return packet, from, nil
		}
		if delay < 4*time.Second {
			delay *= 2
		}
	}
}

func (client *clientTransport) send(message []byte, remote *net.UDPAddr, natt bool) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if natt {
		message = append([]byte{0, 0, 0, 0}, message...)
	}
	_, err := client.conn.WriteToUDP(message, remote)
	return err
}

func (client *clientTransport) start() {
	client.runContext, client.cancelRun = context.WithCancel(context.Background())
	go client.receiveLoop()
	go client.packetLoop()
	if client.natt {
		go client.keepaliveLoop()
	}
}

func (client *clientTransport) receiveLoop() {
	buffer := make([]byte, 65535)
	for {
		n, from, err := client.conn.ReadFromUDP(buffer)
		if err != nil {
			if client.runContext.Err() == nil {
				client.fail(fmt.Errorf("ikev2: UDP receive: %w", err))
			}
			return
		}
		if !from.IP.Equal(client.settings.ikeAddr.IP) {
			continue
		}
		packet := append([]byte(nil), buffer[:n]...)
		if len(packet) == 1 && packet[0] == 0xff {
			continue
		}
		if len(packet) >= 4 && binary.BigEndian.Uint32(packet[:4]) == 0 {
			client.handleIKE(packet[4:], from, true)
			continue
		}
		if from.Port == client.settings.ikeAddr.Port {
			client.handleIKE(packet, from, false)
			continue
		}
		client.handleESP(packet)
	}
}

func (client *clientTransport) handleESP(value []byte) {
	inner, err := client.esp.decapsulate(value)
	if err != nil || len(inner) < 20 || !net.IP(inner[16:20]).Equal(client.assigned) ||
		!selectorsContain(client.remoteSelectors, net.IP(inner[12:16])) {
		return
	}
	_ = client.device.WritePacket(client.runContext, inner)
}

func (client *clientTransport) packetLoop() {
	for {
		inner, err := client.device.ReadPacket(client.runContext)
		if err != nil {
			if client.runContext.Err() == nil {
				client.fail(fmt.Errorf("ikev2: packet device: %w", err))
			}
			return
		}
		if len(inner) < 20 || !net.IP(inner[12:16]).Equal(client.assigned) ||
			!selectorsContain(client.remoteSelectors, net.IP(inner[16:20])) {
			continue
		}
		value, err := client.esp.encapsulate(inner)
		if err != nil {
			client.fail(err)
			return
		}
		client.writeMu.Lock()
		_, err = client.conn.WriteToUDP(value, client.settings.nattAddr)
		client.writeMu.Unlock()
		if err != nil {
			client.fail(fmt.Errorf("ikev2: send ESP: %w", err))
			return
		}
	}
}

func (client *clientTransport) handleIKE(raw []byte, from *net.UDPAddr, natt bool) {
	header, inner, err := decryptMessage(raw, client.keys, false)
	if err != nil || header.initiatorSPI != client.initiatorSPI || header.responderSPI != client.responderSPI || header.flags&flagResponse != 0 {
		return
	}
	responseHeader := ikeHeader{
		initiatorSPI: client.initiatorSPI, responderSPI: client.responderSPI,
		exchange: header.exchange, flags: flagInitiator | flagResponse, messageID: header.messageID,
	}
	var response []payload
	switch header.exchange {
	case exchangeInformation:
		// Empty INFORMATIONAL responses acknowledge liveness and Delete requests.
	case exchangeCreateChild:
		response = []payload{notifyPayload(notifyNoAdditionalSAs, nil)}
	default:
		return
	}
	message, err := encryptMessage(responseHeader, response, client.keys, true)
	if err == nil {
		_ = client.send(message, from, natt)
	}
	if _, deleted := firstPayload(inner, payloadDelete); deleted {
		client.fail(nil)
	}
}

func (client *clientTransport) keepaliveLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			client.writeMu.Lock()
			_, _ = client.conn.WriteToUDP([]byte{0xff}, client.settings.nattAddr)
			client.writeMu.Unlock()
		case <-client.runContext.Done():
			return
		}
	}
}

func (client *clientTransport) Close() error {
	client.closeOnce.Do(func() {
		if client.cancelRun != nil {
			header := ikeHeader{
				initiatorSPI: client.initiatorSPI, responderSPI: client.responderSPI,
				exchange: exchangeInformation, flags: flagInitiator, messageID: 2,
			}
			if message, err := encryptMessage(header, []payload{deleteIKEPayload()}, client.keys, true); err == nil {
				remote := client.settings.ikeAddr
				if client.natt {
					remote = client.settings.nattAddr
				}
				_ = client.send(message, remote, client.natt)
			}
			client.cancelRun()
		}
		_ = client.conn.Close()
	})
	return nil
}

func (client *clientTransport) fail(err error) {
	client.failOnce.Do(func() {
		if client.cancelRun != nil {
			client.cancelRun()
		}
		_ = client.conn.Close()
		client.done <- err
	})
}

func parseAssignedIPv4(data []byte) (net.IP, int, error) {
	kind, attributes, err := parseConfig(data)
	if err != nil || kind != cfgReply {
		return nil, 0, errors.New("invalid CFG_REPLY")
	}
	var address net.IP
	prefixBits := 32
	for _, attribute := range attributes {
		switch attribute.typeID {
		case cfgIPv4:
			if len(attribute.value) == 4 && address == nil {
				address = append(net.IP(nil), attribute.value...)
			}
		case cfgNetmask:
			if len(attribute.value) == 4 {
				ones, bits := net.IPMask(attribute.value).Size()
				if bits != 32 {
					return nil, 0, errors.New("responder supplied a non-contiguous IPv4 netmask")
				}
				prefixBits = ones
			}
		}
	}
	if address == nil || address.IsUnspecified() {
		return nil, 0, errors.New("responder did not assign an IPv4 address")
	}
	return address, prefixBits, nil
}

func notifyError(payloads []payload) error {
	for _, item := range payloads {
		kind, _, ok := notifyType(item)
		if !ok || kind >= 16384 {
			continue
		}
		switch kind {
		case notifyNoProposalChosen:
			return errors.New("peer rejected the cryptographic proposal")
		case notifyInvalidKE:
			return errors.New("peer rejected the Diffie-Hellman group")
		case notifyAuthenticationFailed:
			return errors.New("peer rejected the IKE identity or authentication credentials")
		case notifyInternalAddressFail:
			return errors.New("peer could not allocate an internal address")
		case notifyTSUnacceptable:
			return errors.New("peer rejected the traffic selectors")
		default:
			return fmt.Errorf("peer returned IKEv2 error notify %d", kind)
		}
	}
	return nil
}

func selectorsContain(selectors [][2]net.IP, address net.IP) bool {
	value := ipv4Key(address)
	for _, selector := range selectors {
		if ipv4Key(selector[0]) <= value && value <= ipv4Key(selector[1]) {
			return true
		}
	}
	return false
}

var _ govpn.Client = (*Client)(nil)
