package ikev2

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
)

type Server struct{ Config ServerConfig }

func NewServer(config ServerConfig) (*Server, error) {
	if _, err := resolveServerSettings(config); err != nil {
		return nil, err
	}
	return &Server{Config: config}, nil
}

func (server *Server) Start(ctx context.Context) (*govpn.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, err := resolveServerSettings(server.Config)
	if err != nil {
		return nil, err
	}
	ikeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: settings.listenIP, Port: settings.ikePort})
	if err != nil {
		return nil, fmt.Errorf("ikev2: bind IKE UDP/%d: %w", settings.ikePort, err)
	}
	nattConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: settings.listenIP, Port: settings.nattPort})
	if err != nil {
		_ = ikeConn.Close()
		return nil, fmt.Errorf("ikev2: bind NAT-T UDP/%d: %w", settings.nattPort, err)
	}
	device, err := packet.New("ikev2-server", settings.mtu)
	if err != nil {
		_ = ikeConn.Close()
		_ = nattConn.Close()
		return nil, err
	}
	runContext, cancelRun := context.WithCancel(ctx)
	transport := newServerTransport(settings, ikeConn, nattConn, device)
	done := make(chan error, 1)
	go func() { done <- transport.serve(runContext) }()
	closeTransport := func() error {
		cancelRun()
		return transport.close()
	}
	session, err := govpn.NewSession(
		[]netip.Prefix{netip.PrefixFrom(settings.gateway, settings.network.Bits())},
		uint32(settings.mtu), device, closeTransport, done,
	)
	if err != nil {
		cancelRun()
		_ = transport.close()
		return nil, err
	}
	settings.logger.Printf("[ikev2] responder listening on UDP/%d and UDP/%d", settings.ikePort, settings.nattPort)
	return session, nil
}

type serverTransport struct {
	settings serverSettings
	ikeConn  *net.UDPConn
	nattConn *net.UDPConn
	device   *packet.Device
	pool     *addressPool

	mu          sync.Mutex
	byInitiator map[uint64]*serverPeer
	bySPI       map[uint32]*serverPeer
	byIP        map[uint32]*serverPeer
	closed      bool
	closeOnce   sync.Once
	context     context.Context
}

func newServerTransport(settings serverSettings, ikeConn, nattConn *net.UDPConn, device *packet.Device) *serverTransport {
	return &serverTransport{
		settings: settings, ikeConn: ikeConn, nattConn: nattConn, device: device,
		pool:        newAddressPool(settings.network, settings.gateway),
		byInitiator: make(map[uint64]*serverPeer), bySPI: make(map[uint32]*serverPeer),
		byIP: make(map[uint32]*serverPeer),
	}
}

func (server *serverTransport) serve(ctx context.Context) error {
	server.context = ctx
	errorsChannel := make(chan error, 3)
	go func() { errorsChannel <- server.receiveIKE() }()
	go func() { errorsChannel <- server.receiveNATT() }()
	go func() { errorsChannel <- server.packetLoop() }()
	select {
	case <-ctx.Done():
		_ = server.close()
		return nil
	case err := <-errorsChannel:
		wasClosed := server.isClosed()
		_ = server.close()
		if wasClosed || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (server *serverTransport) close() error {
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closed = true
		peers := make([]*serverPeer, 0, len(server.byInitiator))
		for _, peer := range server.byInitiator {
			peers = append(peers, peer)
		}
		server.mu.Unlock()
		_ = server.ikeConn.Close()
		_ = server.nattConn.Close()
		for _, peer := range peers {
			server.removePeer(peer)
		}
	})
	return nil
}

func (server *serverTransport) isClosed() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.closed
}

func (server *serverTransport) receiveIKE() error {
	buffer := make([]byte, 65535)
	for {
		n, address, err := server.ikeConn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		server.dispatchIKE(append([]byte(nil), buffer[:n]...), address, false)
	}
}

func (server *serverTransport) receiveNATT() error {
	buffer := make([]byte, 65535)
	for {
		n, address, err := server.nattConn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		packet := append([]byte(nil), buffer[:n]...)
		if len(packet) == 1 && packet[0] == 0xff {
			continue
		}
		if len(packet) >= 4 && binary.BigEndian.Uint32(packet[:4]) == 0 {
			server.dispatchIKE(packet[4:], address, true)
			continue
		}
		if len(packet) < 4 {
			continue
		}
		server.mu.Lock()
		peer := server.bySPI[binary.BigEndian.Uint32(packet[:4])]
		server.mu.Unlock()
		if peer != nil {
			peer.handleESP(packet, address)
		}
	}
}

func (server *serverTransport) dispatchIKE(raw []byte, address *net.UDPAddr, natt bool) {
	header, err := parseIKEHeader(raw)
	if err != nil || header.flags&flagResponse != 0 || header.flags&flagInitiator == 0 {
		return
	}
	server.mu.Lock()
	peer := server.byInitiator[header.initiatorSPI]
	if peer == nil && header.exchange == exchangeIKEInit && header.messageID == 0 && header.responderSPI == 0 && !server.closed {
		peer = &serverPeer{server: server, initiatorSPI: header.initiatorSPI, address: cloneUDPAddress(address)}
		server.byInitiator[header.initiatorSPI] = peer
	}
	server.mu.Unlock()
	if peer == nil {
		return
	}
	remove := peer.handleIKE(raw, header, address, natt)
	if remove {
		server.removePeer(peer)
	}
}

func (server *serverTransport) packetLoop() error {
	for {
		packetValue, err := server.device.ReadPacket(server.context)
		if err != nil {
			return err
		}
		destination := packetDestination(packetValue)
		server.mu.Lock()
		peer := server.byIP[ipv4Key(destination)]
		server.mu.Unlock()
		if peer != nil {
			peer.sendESP(packetValue)
		}
	}
}

func (server *serverTransport) removePeer(peer *serverPeer) {
	peer.mu.Lock()
	if peer.closed {
		peer.mu.Unlock()
		return
	}
	peer.closed = true
	address := append(net.IP(nil), peer.assigned...)
	inboundSPI := peer.inboundSPI
	peer.mu.Unlock()

	server.mu.Lock()
	if server.byInitiator[peer.initiatorSPI] == peer {
		delete(server.byInitiator, peer.initiatorSPI)
	}
	if inboundSPI != 0 && server.bySPI[inboundSPI] == peer {
		delete(server.bySPI, inboundSPI)
	}
	if address != nil && server.byIP[ipv4Key(address)] == peer {
		delete(server.byIP, ipv4Key(address))
	}
	server.mu.Unlock()
	if address != nil {
		server.pool.release(address)
	}
}

type serverPeer struct {
	server       *serverTransport
	initiatorSPI uint64

	mu            sync.Mutex
	responderSPI  uint64
	address       *net.UDPAddr
	natt          bool
	ni, nr        []byte
	keys          ikeKeys
	message1      []byte
	message2      []byte
	initRequest   []byte
	initResponse  []byte
	initNATT      bool
	authRequest   []byte
	authResponse  []byte
	authNATT      bool
	lastRequest   []byte
	lastResponse  []byte
	lastNATT      bool
	esp           *espSA
	inboundSPI    uint32
	assigned      net.IP
	established   bool
	nextRequestID uint32
	closed        bool

	clientID      identity
	eapInitial    []payload
	eapStage      uint8
	eapIdentifier uint8
	eapMSCHAPID   uint8
	eapChallenge  [16]byte
	eapMSK        []byte
}

func (peer *serverPeer) handleIKE(raw []byte, header ikeHeader, address *net.UDPAddr, receivedNATT bool) bool {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.closed {
		return false
	}
	if len(peer.initRequest) != 0 && string(peer.initRequest) == string(raw) {
		_ = peer.sendIKE(peer.initResponse, address, peer.initNATT)
		return false
	}
	if len(peer.authRequest) != 0 && string(peer.authRequest) == string(raw) {
		_ = peer.sendIKE(peer.authResponse, address, peer.authNATT)
		return false
	}
	if len(peer.lastRequest) != 0 && string(peer.lastRequest) == string(raw) {
		_ = peer.sendIKE(peer.lastResponse, address, peer.lastNATT)
		return false
	}
	if header.exchange == exchangeIKEInit && header.messageID == 0 && header.responderSPI == 0 && peer.responderSPI == 0 {
		return peer.handleInit(raw, header, address, receivedNATT)
	}
	if header.responderSPI != peer.responderSPI || peer.responderSPI == 0 {
		return false
	}
	if header.exchange == exchangeIKEAuth && !peer.established {
		if header.messageID == 1 && peer.eapStage == 0 {
			return peer.handleFirstAuth(raw, header, address, receivedNATT)
		}
		if peer.eapStage != 0 {
			return peer.handleEAPAuth(raw, header, address, receivedNATT)
		}
		return false
	}
	if !peer.established {
		return false
	}
	return peer.handleEstablished(raw, header, address, receivedNATT)
}

func (peer *serverPeer) handleInit(raw []byte, header ikeHeader, address *net.UDPAddr, receivedNATT bool) bool {
	payloads, err := parseMessagePayloads(raw, header)
	if err != nil {
		return true
	}
	sa, ok := firstPayload(payloads, payloadSA)
	if !ok {
		return true
	}
	ke, ok := firstPayload(payloads, payloadKE)
	if !ok {
		return true
	}
	if len(ke.data) < 2 {
		return true
	}
	group := binary.BigEndian.Uint16(ke.data[:2])
	if group != dhMODP2048 && !(group == dhMODP1024 && peer.server.settings.allowLegacyMODP1024) {
		preferred := []byte{0, dhMODP2048}
		peer.respondInitError(header, address, receivedNATT, notifyInvalidKE, preferred)
		return true
	}
	if _, ok := selectProposal(sa.data, protocolIKE, group); !ok {
		peer.respondInitError(header, address, receivedNATT, notifyNoProposalChosen, nil)
		return true
	}
	peerPublic, err := parseKeyExchange(ke.data, group)
	if err != nil {
		preferred := []byte{0, dhMODP2048}
		peer.respondInitError(header, address, receivedNATT, notifyInvalidKE, preferred)
		return true
	}
	nonce, ok := firstPayload(payloads, payloadNonce)
	if !ok || len(nonce.data) < 16 {
		return true
	}
	responderSPI, err := randomUint64()
	if err != nil {
		return true
	}
	dh, public, err := generateMODPKey(group)
	if err != nil {
		return true
	}
	peer.nr, err = randomBytes(32)
	if err != nil {
		return true
	}
	peer.ni = append([]byte(nil), nonce.data...)
	peer.responderSPI = responderSPI
	shared, err := dh.secret(peerPublic)
	if err != nil {
		return true
	}
	peer.keys = deriveIKEKeys(peer.ni, peer.nr, shared, peer.initiatorSPI, responderSPI)
	expectedSource := natDetectionHash(peer.initiatorSPI, header.responderSPI, address.IP, address.Port)
	expectedDestination := natDetectionHash(peer.initiatorSPI, header.responderSPI, peer.server.settings.publicIP, peer.server.settings.ikePort)
	peer.natt = peer.server.settings.forceEncapsulation || receivedNATT || detectsNAT(payloads, expectedSource, expectedDestination)
	natSourcePort := peer.server.settings.ikePort
	if receivedNATT {
		natSourcePort = peer.server.settings.nattPort
	}
	if peer.server.settings.forceEncapsulation {
		natSourcePort = 0
	}
	responseHeader := ikeHeader{
		initiatorSPI: peer.initiatorSPI, responderSPI: responderSPI,
		exchange: exchangeIKEInit, flags: flagResponse,
	}
	response, err := marshalMessage(responseHeader, []payload{
		ikeProposal(group), keyExchangePayload(group, public), {typeID: payloadNonce, data: peer.nr},
		notifyPayload(notifyNATSource, natDetectionHash(peer.initiatorSPI, responderSPI, peer.server.settings.publicIP, natSourcePort)),
		notifyPayload(notifyNATDestination, natDetectionHash(peer.initiatorSPI, responderSPI, address.IP, address.Port)),
	})
	if err != nil {
		return true
	}
	peer.message1 = append([]byte(nil), raw...)
	peer.message2 = append([]byte(nil), response...)
	peer.initRequest = append([]byte(nil), raw...)
	peer.initResponse = append([]byte(nil), response...)
	peer.initNATT = receivedNATT
	peer.cache(raw, response, receivedNATT)
	_ = peer.sendIKE(response, address, receivedNATT)
	return false
}

func (peer *serverPeer) respondInitError(header ikeHeader, address *net.UDPAddr, natt bool, kind uint16, data []byte) {
	if peer.responderSPI == 0 {
		peer.responderSPI, _ = randomUint64()
	}
	response, err := marshalMessage(ikeHeader{
		initiatorSPI: header.initiatorSPI, responderSPI: peer.responderSPI,
		exchange: exchangeIKEInit, flags: flagResponse,
	}, []payload{notifyPayload(kind, data)})
	if err == nil {
		_ = peer.sendIKE(response, address, natt)
	}
}

func (peer *serverPeer) handleFirstAuth(raw []byte, requestHeader ikeHeader, address *net.UDPAddr, receivedNATT bool) bool {
	header, inner, err := decryptMessage(raw, peer.keys, true)
	if err != nil || header.exchange != exchangeIKEAuth || header.messageID != requestHeader.messageID {
		return false
	}
	idPayload, ok := firstPayload(inner, payloadIDi)
	if !ok {
		peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
		return false
	}
	clientID, err := decodeIdentity(idPayload.data)
	if err != nil {
		peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
		return false
	}
	peer.clientID = clientID
	if _, hasAuth := firstPayload(inner, payloadAUTH); !hasAuth {
		return peer.startEAP(raw, header.messageID, inner, address, receivedNATT)
	}
	return peer.handlePSKAuth(raw, header.messageID, inner, idPayload, clientID, address, receivedNATT)
}

func (peer *serverPeer) handlePSKAuth(raw []byte, messageID uint32, inner []payload, idPayload payload, clientID identity, address *net.UDPAddr, receivedNATT bool) bool {
	psk, known := peer.server.settings.users[clientID.key()]
	authItem, hasAuth := firstPayload(inner, payloadAUTH)
	receivedAuth, authErr := parseAuth(authItem.data)
	if !known || !hasAuth || authErr != nil {
		peer.respondAuthError(raw, address, receivedNATT, messageID, notifyAuthenticationFailed)
		return false
	}
	expectedAuth := authenticationValue(psk, peer.message1, peer.nr, peer.keys.skPI, idPayload.data)
	if !secretEqual(receivedAuth, expectedAuth) {
		peer.respondAuthError(raw, address, receivedNATT, messageID, notifyAuthenticationFailed)
		return false
	}
	return peer.establishChild(raw, messageID, inner, clientID.key(), psk, true, address, receivedNATT)
}

func (peer *serverPeer) startEAP(raw []byte, messageID uint32, inner []payload, address *net.UDPAddr, receivedNATT bool) bool {
	if len(peer.server.settings.passwordUsers) == 0 {
		peer.respondAuthError(raw, address, receivedNATT, messageID, notifyAuthenticationFailed)
		return false
	}
	if _, kind := validateChildRequest(inner); kind != 0 {
		peer.respondAuthError(raw, address, receivedNATT, messageID, kind)
		return false
	}
	challenge, err := randomBytes(16)
	if err != nil {
		return true
	}
	identifierValue, err := randomBytes(1)
	if err != nil {
		return true
	}
	identifier := identifierValue[0]
	if identifier == 0 {
		identifier = 1
	}
	copy(peer.eapChallenge[:], challenge)
	peer.eapIdentifier = identifier
	peer.eapMSCHAPID = identifier
	serverIDBody := peer.server.settings.identity.body()
	signed := signedOctets(peer.message2, peer.ni, peer.keys.skPR, serverIDBody)
	signature, err := signRSAAuthentication(peer.server.settings.privateKey, signed)
	if err != nil {
		return true
	}
	responseInner := []payload{{typeID: payloadIDr, data: serverIDBody}}
	for _, certificate := range peer.server.settings.certificates {
		responseInner = append(responseInner, certificatePayload(certificate.Raw))
	}
	responseInner = append(responseInner,
		rsaAuthPayload(signature),
		eapPayload(buildMSCHAPChallenge(identifier, peer.eapChallenge, "govpn")),
	)
	response, err := encryptMessage(ikeHeader{
		initiatorSPI: peer.initiatorSPI, responderSPI: peer.responderSPI,
		exchange: exchangeIKEAuth, flags: flagResponse, messageID: messageID,
	}, responseInner, peer.keys, false)
	if err != nil {
		return true
	}
	peer.eapInitial = clonePayloads(inner)
	peer.eapStage = 1
	peer.nextRequestID = messageID + 1
	peer.address = cloneUDPAddress(address)
	peer.natt = peer.natt || receivedNATT
	peer.cache(raw, response, peer.natt)
	_ = peer.sendIKE(response, address, peer.natt)
	return false
}

func (peer *serverPeer) handleEAPAuth(raw []byte, requestHeader ikeHeader, address *net.UDPAddr, receivedNATT bool) bool {
	if requestHeader.messageID != peer.nextRequestID {
		return false
	}
	header, inner, err := decryptMessage(raw, peer.keys, true)
	if err != nil || header.exchange != exchangeIKEAuth || header.messageID != requestHeader.messageID {
		return false
	}
	switch peer.eapStage {
	case 1:
		eapItem, ok := firstPayload(inner, payloadEAP)
		if !ok {
			peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
			return false
		}
		value, err := parseMSCHAPResponse(eapItem.data, peer.eapIdentifier)
		if err != nil {
			peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
			return false
		}
		password, known := peer.server.settings.passwordUsers[value.username]
		if !known {
			password, known = peer.server.settings.passwordUsers[mschapUsername(value.username)]
		}
		expected := generateNTResponse(peer.eapChallenge, value.peerChallenge, mschapUsername(value.username), password)
		if !known || !secretEqual(value.ntResponse[:], expected[:]) {
			peer.respondEAP(raw, header.messageID, marshalEAPResult(eapFailure, peer.eapIdentifier), address, receivedNATT)
			return false
		}
		peer.eapMSK = generateMSCHAPMSK(password, value.ntResponse)
		authenticator := authenticatorResponse(peer.eapChallenge, value.peerChallenge, mschapUsername(value.username), password, value.ntResponse)
		peer.eapIdentifier++
		response := buildMSCHAPSuccessRequest(peer.eapIdentifier, peer.eapMSCHAPID, authenticator)
		peer.eapStage = 2
		peer.nextRequestID = header.messageID + 1
		peer.respondEAP(raw, header.messageID, response, address, receivedNATT)
		return false
	case 2:
		eapItem, ok := firstPayload(inner, payloadEAP)
		if !ok || !isMSCHAPSuccessResponse(eapItem.data, peer.eapIdentifier) {
			peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
			return false
		}
		peer.eapStage = 3
		peer.nextRequestID = header.messageID + 1
		peer.respondEAP(raw, header.messageID, marshalEAPResult(eapSuccess, peer.eapIdentifier), address, receivedNATT)
		return false
	case 3:
		authItem, ok := firstPayload(inner, payloadAUTH)
		if !ok {
			peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
			return false
		}
		received, err := parseAuth(authItem.data)
		idPayload, hasID := firstPayload(peer.eapInitial, payloadIDi)
		if err != nil || !hasID {
			peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
			return false
		}
		expected := authenticationValue(peer.eapMSK, peer.message1, peer.nr, peer.keys.skPI, idPayload.data)
		if !secretEqual(received, expected) {
			peer.respondAuthError(raw, address, receivedNATT, header.messageID, notifyAuthenticationFailed)
			return false
		}
		return peer.establishChild(raw, header.messageID, peer.eapInitial, peer.clientID.key(), peer.eapMSK, false, address, receivedNATT)
	}
	return false
}

func validateChildRequest(inner []payload) (uint32, uint16) {
	childSA, ok := firstPayload(inner, payloadSA)
	if !ok {
		return 0, notifyNoProposalChosen
	}
	clientSPIBytes, ok := selectProposal(childSA.data, protocolESP)
	if !ok || len(clientSPIBytes) != 4 {
		return 0, notifyNoProposalChosen
	}
	clientSPI := binary.BigEndian.Uint32(clientSPIBytes)
	tsi, hasTSi := firstPayload(inner, payloadTSi)
	tsr, hasTSr := firstPayload(inner, payloadTSr)
	if !hasTSi || !hasTSr {
		return 0, notifyTSUnacceptable
	}
	if _, err := parseIPv4Selectors(tsi.data); err != nil {
		return 0, notifyTSUnacceptable
	}
	if _, err := parseIPv4Selectors(tsr.data); err != nil {
		return 0, notifyTSUnacceptable
	}
	cp, ok := firstPayload(inner, payloadCP)
	if !ok {
		return 0, notifyInternalAddressFail
	}
	kind, requested, err := parseConfig(cp.data)
	if err != nil || kind != cfgRequest || !containsConfigAttribute(requested, cfgIPv4) {
		return 0, notifyInternalAddressFail
	}
	return clientSPI, 0
}

func (peer *serverPeer) establishChild(raw []byte, messageID uint32, inner []payload, authenticatedID string, secret []byte, includeID bool, address *net.UDPAddr, receivedNATT bool) bool {
	clientSPI, kind := validateChildRequest(inner)
	if kind != 0 {
		peer.respondAuthError(raw, address, receivedNATT, messageID, kind)
		return false
	}
	assigned, err := peer.server.pool.allocate()
	if err != nil {
		peer.respondAuthError(raw, address, receivedNATT, messageID, notifyInternalAddressFail)
		return false
	}
	serverSPI, err := randomUint32()
	if err != nil {
		peer.server.pool.release(assigned)
		return true
	}
	serverIDBody := peer.server.settings.identity.body()
	responseAuth := authenticationValue(secret, peer.message2, peer.ni, peer.keys.skPR, serverIDBody)
	mask := net.CIDRMask(peer.server.settings.network.Bits(), 32)
	configAttributes := []configAttribute{
		{typeID: cfgIPv4, value: assigned.To4()},
		{typeID: cfgNetmask, value: append([]byte(nil), mask...)},
	}
	for _, dns := range peer.server.settings.dns {
		configAttributes = append(configAttributes, configAttribute{typeID: cfgDNS, value: dns.To4()})
	}
	responseInner := make([]payload, 0, 6)
	if includeID {
		responseInner = append(responseInner, payload{typeID: payloadIDr, data: serverIDBody})
	}
	responseInner = append(responseInner, authPayload(responseAuth),
		configPayload(cfgReply, configAttributes...),
		espProposal(serverSPI),
		trafficSelectorPayload(payloadTSi, assigned, assigned),
		trafficSelectorPayload(payloadTSr, net.IPv4zero, net.IPv4bcast),
	)
	response, err := encryptMessage(ikeHeader{
		initiatorSPI: peer.initiatorSPI, responderSPI: peer.responderSPI,
		exchange: exchangeIKEAuth, flags: flagResponse, messageID: messageID,
	}, responseInner, peer.keys, false)
	if err != nil {
		peer.server.pool.release(assigned)
		return true
	}
	material := deriveESPKeys(peer.keys, peer.ni, peer.nr)
	peer.esp = newResponderESP(clientSPI, serverSPI, material)
	peer.inboundSPI = serverSPI
	peer.assigned = append(net.IP(nil), assigned...)
	peer.address = cloneUDPAddress(address)
	peer.natt = peer.natt || receivedNATT
	peer.established = true
	peer.nextRequestID = messageID + 1
	peer.server.mu.Lock()
	peer.server.bySPI[serverSPI] = peer
	peer.server.byIP[ipv4Key(assigned)] = peer
	peer.server.mu.Unlock()
	peer.authRequest = append([]byte(nil), raw...)
	peer.authResponse = append([]byte(nil), response...)
	peer.authNATT = peer.natt
	peer.cache(raw, response, peer.natt)
	_ = peer.sendIKE(response, address, peer.natt)
	peer.server.settings.logger.Printf("[ikev2] authenticated %s from %s, assigned %s", authenticatedID, address, assigned)
	return false
}

func (peer *serverPeer) respondEAP(request []byte, messageID uint32, packet []byte, address *net.UDPAddr, natt bool) {
	response, err := encryptMessage(ikeHeader{
		initiatorSPI: peer.initiatorSPI, responderSPI: peer.responderSPI,
		exchange: exchangeIKEAuth, flags: flagResponse, messageID: messageID,
	}, []payload{eapPayload(packet)}, peer.keys, false)
	if err == nil {
		peer.natt = peer.natt || natt
		peer.cache(request, response, peer.natt)
		_ = peer.sendIKE(response, address, peer.natt)
	}
}

func (peer *serverPeer) respondAuthError(request []byte, address *net.UDPAddr, natt bool, messageID uint32, kind uint16) {
	response, err := encryptMessage(ikeHeader{
		initiatorSPI: peer.initiatorSPI, responderSPI: peer.responderSPI,
		exchange: exchangeIKEAuth, flags: flagResponse, messageID: messageID,
	}, []payload{notifyPayload(kind, nil)}, peer.keys, false)
	if err == nil {
		peer.authRequest = append([]byte(nil), request...)
		peer.authResponse = append([]byte(nil), response...)
		peer.authNATT = natt
		peer.cache(request, response, natt)
		_ = peer.sendIKE(response, address, natt)
	}
}

func clonePayloads(value []payload) []payload {
	result := make([]payload, len(value))
	for index, item := range value {
		result[index] = payload{typeID: item.typeID, critical: item.critical, data: append([]byte(nil), item.data...)}
	}
	return result
}

func (peer *serverPeer) handleEstablished(raw []byte, header ikeHeader, address *net.UDPAddr, receivedNATT bool) bool {
	if header.messageID != peer.nextRequestID {
		return false
	}
	decodedHeader, inner, err := decryptMessage(raw, peer.keys, true)
	if err != nil || decodedHeader.messageID != header.messageID {
		return false
	}
	var responseInner []payload
	switch header.exchange {
	case exchangeInformation:
	case exchangeCreateChild:
		responseInner = []payload{notifyPayload(notifyNoAdditionalSAs, nil)}
	default:
		return false
	}
	response, err := encryptMessage(ikeHeader{
		initiatorSPI: peer.initiatorSPI, responderSPI: peer.responderSPI,
		exchange: header.exchange, flags: flagResponse, messageID: header.messageID,
	}, responseInner, peer.keys, false)
	if err != nil {
		return false
	}
	peer.address = cloneUDPAddress(address)
	peer.natt = peer.natt || receivedNATT
	peer.cache(raw, response, peer.natt)
	peer.nextRequestID++
	_ = peer.sendIKE(response, address, peer.natt)
	_, deleting := firstPayload(inner, payloadDelete)
	return deleting
}

func (peer *serverPeer) cache(request, response []byte, natt bool) {
	peer.lastRequest = append(peer.lastRequest[:0], request...)
	peer.lastResponse = append(peer.lastResponse[:0], response...)
	peer.lastNATT = natt
}

func (peer *serverPeer) sendIKE(message []byte, address *net.UDPAddr, natt bool) error {
	if natt {
		value := append([]byte{0, 0, 0, 0}, message...)
		_, err := peer.server.nattConn.WriteToUDP(value, address)
		return err
	}
	_, err := peer.server.ikeConn.WriteToUDP(message, address)
	return err
}

func (peer *serverPeer) handleESP(value []byte, address *net.UDPAddr) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.closed || !peer.established {
		return
	}
	inner, err := peer.esp.decapsulate(value)
	if err != nil || !packetSource(inner).Equal(peer.assigned) {
		return
	}
	peer.address = cloneUDPAddress(address)
	_ = peer.server.device.WritePacket(peer.server.context, inner)
}

func (peer *serverPeer) sendESP(inner []byte) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.closed || !peer.established {
		return
	}
	value, err := peer.esp.encapsulate(inner)
	if err != nil {
		return
	}
	_, _ = peer.server.nattConn.WriteToUDP(value, peer.address)
}

func cloneUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

var _ govpn.Server = (*Server)(nil)
