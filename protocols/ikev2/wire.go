package ikev2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	ikeHeaderLen = 28
	ikeVersion   = 0x20

	payloadNone    = 0
	payloadSA      = 33
	payloadKE      = 34
	payloadIDi     = 35
	payloadIDr     = 36
	payloadCERT    = 37
	payloadCERTReq = 38
	payloadAUTH    = 39
	payloadNonce   = 40
	payloadNotify  = 41
	payloadDelete  = 42
	payloadTSi     = 44
	payloadTSr     = 45
	payloadSK      = 46
	payloadCP      = 47
	payloadEAP     = 48

	exchangeIKEInit     = 34
	exchangeIKEAuth     = 35
	exchangeCreateChild = 36
	exchangeInformation = 37

	flagInitiator = 0x08
	flagVersion   = 0x10
	flagResponse  = 0x20

	protocolIKE = 1
	protocolESP = 3

	transformEncryption = 1
	transformPRF        = 2
	transformIntegrity  = 3
	transformDH         = 4
	transformESN        = 5

	encrAESCBC          = 12
	prfHMACSHA256       = 5
	integHMACSHA256_128 = 12
	dhMODP1024          = 2
	dhMODP2048          = 14
	esnDisabled         = 0

	notifyNoProposalChosen     = 14
	notifyInvalidKE            = 17
	notifyAuthenticationFailed = 24
	notifyNoAdditionalSAs      = 35
	notifyInternalAddressFail  = 36
	notifyTSUnacceptable       = 38
	notifyNATSource            = 16388
	notifyNATDestination       = 16389

	authRSASignature = 1
	authSharedKey    = 2

	idIPv4   = 1
	idFQDN   = 2
	idRFC822 = 3
	idKeyID  = 11
	tsIPv4   = 7

	cfgRequest = 1
	cfgReply   = 2
	cfgIPv4    = 1
	cfgNetmask = 2
	cfgDNS     = 3
	cfgSubnet  = 13
)

type ikeHeader struct {
	initiatorSPI uint64
	responderSPI uint64
	nextPayload  uint8
	version      uint8
	exchange     uint8
	flags        uint8
	messageID    uint32
	length       uint32
}

func parseIKEHeader(raw []byte) (ikeHeader, error) {
	if len(raw) < ikeHeaderLen {
		return ikeHeader{}, errors.New("IKE header is truncated")
	}
	h := ikeHeader{
		initiatorSPI: binary.BigEndian.Uint64(raw[0:8]),
		responderSPI: binary.BigEndian.Uint64(raw[8:16]),
		nextPayload:  raw[16], version: raw[17], exchange: raw[18], flags: raw[19],
		messageID: binary.BigEndian.Uint32(raw[20:24]),
		length:    binary.BigEndian.Uint32(raw[24:28]),
	}
	if h.version>>4 != 2 {
		return ikeHeader{}, fmt.Errorf("unsupported IKE major version %d", h.version>>4)
	}
	if h.length != uint32(len(raw)) {
		return ikeHeader{}, errors.New("IKE message length does not match datagram")
	}
	if h.initiatorSPI == 0 {
		return ikeHeader{}, errors.New("zero initiator SPI")
	}
	return h, nil
}

func marshalIKEHeader(h ikeHeader, length int) []byte {
	raw := make([]byte, ikeHeaderLen)
	binary.BigEndian.PutUint64(raw[0:8], h.initiatorSPI)
	binary.BigEndian.PutUint64(raw[8:16], h.responderSPI)
	raw[16], raw[17], raw[18], raw[19] = h.nextPayload, ikeVersion, h.exchange, h.flags
	binary.BigEndian.PutUint32(raw[20:24], h.messageID)
	binary.BigEndian.PutUint32(raw[24:28], uint32(length))
	return raw
}

type payload struct {
	typeID   uint8
	critical bool
	data     []byte
}

func marshalMessage(h ikeHeader, payloads []payload) ([]byte, error) {
	next, encoded, err := marshalPayloads(payloads)
	if err != nil {
		return nil, err
	}
	h.nextPayload = next
	raw := marshalIKEHeader(h, ikeHeaderLen+len(encoded))
	return append(raw, encoded...), nil
}

func marshalPayloads(payloads []payload) (uint8, []byte, error) {
	if len(payloads) == 0 {
		return payloadNone, nil, nil
	}
	var out []byte
	for index, item := range payloads {
		if len(item.data)+4 > 65535 {
			return 0, nil, errors.New("IKE payload is too large")
		}
		header := make([]byte, 4)
		if index+1 < len(payloads) {
			header[0] = payloads[index+1].typeID
		}
		if item.critical {
			header[1] = 0x80
		}
		binary.BigEndian.PutUint16(header[2:4], uint16(len(item.data)+4))
		out = append(out, header...)
		out = append(out, item.data...)
	}
	return payloads[0].typeID, out, nil
}

func parseMessagePayloads(raw []byte, h ikeHeader) ([]payload, error) {
	return parsePayloads(h.nextPayload, raw[ikeHeaderLen:])
}

func parsePayloads(next uint8, raw []byte) ([]payload, error) {
	var result []payload
	for next != payloadNone {
		if len(raw) < 4 {
			return nil, errors.New("IKE payload header is truncated")
		}
		length := int(binary.BigEndian.Uint16(raw[2:4]))
		if length < 4 || length > len(raw) {
			return nil, errors.New("invalid IKE payload length")
		}
		item := payload{typeID: next, critical: raw[1]&0x80 != 0, data: append([]byte(nil), raw[4:length]...)}
		result = append(result, item)
		following := raw[0]
		raw = raw[length:]
		if next == payloadSK {
			if len(raw) != 0 {
				return nil, errors.New("encrypted payload is not last")
			}
			break
		}
		next = following
	}
	if len(raw) != 0 {
		return nil, errors.New("trailing bytes after IKE payload chain")
	}
	return result, nil
}

func firstPayload(payloads []payload, kind uint8) (payload, bool) {
	for _, item := range payloads {
		if item.typeID == kind {
			return item, true
		}
	}
	return payload{}, false
}

type identity struct {
	typeID uint8
	data   []byte
}

func parseIdentity(value string) (identity, error) {
	if value == "" {
		return identity{}, errors.New("identity is empty")
	}
	if prefix, data, found := strings.Cut(value, ":"); found {
		if data == "" {
			return identity{}, errors.New("identity value is empty")
		}
		switch strings.ToLower(prefix) {
		case "keyid":
			return identity{typeID: idKeyID, data: []byte(data)}, nil
		case "fqdn":
			return identity{typeID: idFQDN, data: []byte(data)}, nil
		case "email":
			return identity{typeID: idRFC822, data: []byte(data)}, nil
		case "ipv4":
			ip := net.ParseIP(data).To4()
			if ip == nil {
				return identity{}, errors.New("invalid IPv4 identity")
			}
			return identity{typeID: idIPv4, data: append([]byte(nil), ip...)}, nil
		}
	}
	if ip := net.ParseIP(value); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return identity{typeID: idIPv4, data: append([]byte(nil), v4...)}, nil
		}
		return identity{}, errors.New("IPv6 identities are not supported")
	}
	kind := uint8(idFQDN)
	if bytes.ContainsRune([]byte(value), '@') {
		kind = idRFC822
	}
	return identity{typeID: kind, data: []byte(value)}, nil
}

func decodeIdentity(data []byte) (identity, error) {
	if len(data) < 4 {
		return identity{}, errors.New("identity payload is truncated")
	}
	id := identity{typeID: data[0], data: append([]byte(nil), data[4:]...)}
	switch id.typeID {
	case idIPv4:
		if len(id.data) != net.IPv4len {
			return identity{}, errors.New("invalid IPv4 identity")
		}
	case idFQDN, idRFC822, idKeyID:
		if len(id.data) == 0 {
			return identity{}, errors.New("empty identity value")
		}
	default:
		return identity{}, fmt.Errorf("unsupported identity type %d", id.typeID)
	}
	return id, nil
}

func (id identity) body() []byte {
	return append([]byte{id.typeID, 0, 0, 0}, id.data...)
}

func (id identity) key() string {
	if id.typeID == idIPv4 {
		return fmt.Sprintf("%d:%s", id.typeID, net.IP(id.data).String())
	}
	return fmt.Sprintf("%d:%s", id.typeID, id.data)
}

func (id identity) equal(other identity) bool {
	return id.typeID == other.typeID && bytes.Equal(id.data, other.data)
}

type transform struct {
	typeID uint8
	id     uint16
	keyLen uint16
}

func ikeProposal(group uint16) payload {
	return proposalPayload(protocolIKE, nil, []transform{
		{typeID: transformEncryption, id: encrAESCBC, keyLen: 256},
		{typeID: transformPRF, id: prfHMACSHA256},
		{typeID: transformIntegrity, id: integHMACSHA256_128},
		{typeID: transformDH, id: group},
	})
}

func espProposal(spi uint32) payload {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], spi)
	return proposalPayload(protocolESP, value[:], []transform{
		{typeID: transformEncryption, id: encrAESCBC, keyLen: 256},
		{typeID: transformIntegrity, id: integHMACSHA256_128},
		{typeID: transformESN, id: esnDisabled},
	})
}

func proposalPayload(protocol uint8, spi []byte, transforms []transform) payload {
	proposal := make([]byte, 8, 8+len(spi)+12*len(transforms))
	proposal[4], proposal[5], proposal[6], proposal[7] = 1, protocol, uint8(len(spi)), uint8(len(transforms))
	proposal = append(proposal, spi...)
	for index, item := range transforms {
		length := 8
		if item.keyLen != 0 {
			length += 4
		}
		encoded := make([]byte, length)
		if index+1 < len(transforms) {
			encoded[0] = 3
		}
		binary.BigEndian.PutUint16(encoded[2:4], uint16(length))
		encoded[4] = item.typeID
		binary.BigEndian.PutUint16(encoded[6:8], item.id)
		if item.keyLen != 0 {
			binary.BigEndian.PutUint16(encoded[8:10], 0x800e)
			binary.BigEndian.PutUint16(encoded[10:12], item.keyLen)
		}
		proposal = append(proposal, encoded...)
	}
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	return payload{typeID: payloadSA, data: proposal}
}

func selectProposal(data []byte, protocol uint8, dhGroup ...uint16) ([]byte, bool) {
	group := uint16(0)
	if len(dhGroup) != 0 {
		group = dhGroup[0]
	}
	for len(data) >= 8 {
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if length < 8 || length > len(data) {
			return nil, false
		}
		proposal := data[:length]
		spiLen := int(proposal[6])
		expectedSPILen := 0
		if protocol == protocolESP {
			expectedSPILen = 4
		}
		if proposal[5] == protocol && spiLen == expectedSPILen && 8+spiLen <= len(proposal) && proposalMatches(proposal[8+spiLen:], int(proposal[7]), protocol, group) {
			return append([]byte(nil), proposal[8:8+spiLen]...), true
		}
		data = data[length:]
	}
	return nil, false
}

func proposalMatches(raw []byte, count int, protocol uint8, dhGroup uint16) bool {
	seen := make(map[uint8]bool)
	for index := 0; index < count; index++ {
		if len(raw) < 8 {
			return false
		}
		length := int(binary.BigEndian.Uint16(raw[2:4]))
		if length < 8 || length > len(raw) {
			return false
		}
		kind, id := raw[4], binary.BigEndian.Uint16(raw[6:8])
		switch kind {
		case transformEncryption:
			if id == encrAESCBC && hasKeyLength(raw[8:length], 256) {
				seen[kind] = true
			}
		case transformPRF:
			if protocol != protocolIKE {
				return false
			}
			if id == prfHMACSHA256 && length == 8 {
				seen[kind] = true
			}
		case transformIntegrity:
			if id == integHMACSHA256_128 && length == 8 {
				seen[kind] = true
			}
		case transformDH:
			if protocol != protocolIKE {
				return false
			}
			if id == dhGroup && length == 8 {
				seen[kind] = true
			}
		case transformESN:
			if protocol != protocolESP {
				return false
			}
			if id == esnDisabled && length == 8 {
				seen[kind] = true
			}
		default:
			return false
		}
		raw = raw[length:]
	}
	if len(raw) != 0 {
		return false
	}
	if protocol == protocolIKE {
		return seen[transformEncryption] && seen[transformPRF] && seen[transformIntegrity] && seen[transformDH]
	}
	return seen[transformEncryption] && seen[transformIntegrity]
}

func hasKeyLength(attributes []byte, want uint16) bool {
	for len(attributes) >= 4 {
		kind := binary.BigEndian.Uint16(attributes[0:2])
		if kind&0x8000 != 0 {
			if kind&0x7fff == 14 && binary.BigEndian.Uint16(attributes[2:4]) == want {
				return true
			}
			attributes = attributes[4:]
			continue
		}
		length := int(binary.BigEndian.Uint16(attributes[2:4]))
		if len(attributes) < 4+length {
			return false
		}
		attributes = attributes[4+length:]
	}
	return false
}

func keyExchangePayload(group uint16, public []byte) payload {
	data := make([]byte, 4, 4+len(public))
	binary.BigEndian.PutUint16(data[0:2], group)
	return payload{typeID: payloadKE, data: append(data, public...)}
}

func parseKeyExchange(data []byte, group uint16) ([]byte, error) {
	size := 0
	switch group {
	case dhMODP1024:
		size = 128
	case dhMODP2048:
		size = 256
	}
	if size == 0 || len(data) != 4+size || binary.BigEndian.Uint16(data[:2]) != group {
		return nil, fmt.Errorf("invalid MODP group %d key exchange", group)
	}
	return append([]byte(nil), data[4:]...), nil
}

func notifyPayload(kind uint16, data []byte) payload {
	body := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint16(body[2:4], kind)
	return payload{typeID: payloadNotify, data: append(body, data...)}
}

func notifyType(item payload) (uint16, []byte, bool) {
	if item.typeID != payloadNotify || len(item.data) < 4 {
		return 0, nil, false
	}
	spiLen := int(item.data[1])
	if len(item.data) < 4+spiLen {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(item.data[2:4]), item.data[4+spiLen:], true
}

func deleteIKEPayload() payload {
	return payload{typeID: payloadDelete, data: []byte{protocolIKE, 0, 0, 0}}
}

func authPayload(value []byte) payload {
	return payload{typeID: payloadAUTH, data: append([]byte{authSharedKey, 0, 0, 0}, value...)}
}

func rsaAuthPayload(value []byte) payload {
	return payload{typeID: payloadAUTH, data: append([]byte{authRSASignature, 0, 0, 0}, value...)}
}

func parseAuth(data []byte) ([]byte, error) {
	if len(data) < 5 || data[0] != authSharedKey {
		return nil, errors.New("unsupported authentication method")
	}
	return data[4:], nil
}

func parseRSAAuth(data []byte) ([]byte, error) {
	if len(data) < 5 || data[0] != authRSASignature {
		return nil, errors.New("unsupported responder authentication method")
	}
	return data[4:], nil
}

func certificatePayload(der []byte) payload {
	return payload{typeID: payloadCERT, data: append([]byte{4}, der...)}
}

func eapPayload(packet []byte) payload {
	return payload{typeID: payloadEAP, data: append([]byte(nil), packet...)}
}

func trafficSelectorPayload(kind uint8, start, end net.IP) payload {
	body := make([]byte, 4, 20)
	body[0] = 1
	selector := make([]byte, 16)
	selector[0] = tsIPv4
	binary.BigEndian.PutUint16(selector[2:4], 16)
	binary.BigEndian.PutUint16(selector[6:8], 65535)
	copy(selector[8:12], start.To4())
	copy(selector[12:16], end.To4())
	return payload{typeID: kind, data: append(body, selector...)}
}

func parseIPv4Selectors(data []byte) ([][2]net.IP, error) {
	if len(data) < 4 {
		return nil, errors.New("traffic selector payload is truncated")
	}
	count := int(data[0])
	data = data[4:]
	result := make([][2]net.IP, 0, count)
	for index := 0; index < count; index++ {
		if len(data) < 16 || data[0] != tsIPv4 || data[1] != 0 ||
			binary.BigEndian.Uint16(data[2:4]) != 16 ||
			binary.BigEndian.Uint16(data[4:6]) != 0 || binary.BigEndian.Uint16(data[6:8]) != 65535 {
			return nil, errors.New("unsupported traffic selector")
		}
		start := append(net.IP(nil), data[8:12]...)
		end := append(net.IP(nil), data[12:16]...)
		if binary.BigEndian.Uint32(start) > binary.BigEndian.Uint32(end) {
			return nil, errors.New("reversed traffic selector range")
		}
		result = append(result, [2]net.IP{start, end})
		data = data[16:]
	}
	if len(data) != 0 || len(result) == 0 {
		return nil, errors.New("invalid traffic selector list")
	}
	return result, nil
}

type configAttribute struct {
	typeID uint16
	value  []byte
}

func configPayload(kind uint8, attributes ...configAttribute) payload {
	body := []byte{kind, 0, 0, 0}
	for _, attribute := range attributes {
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[:2], attribute.typeID)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(attribute.value)))
		body = append(body, header...)
		body = append(body, attribute.value...)
	}
	return payload{typeID: payloadCP, data: body}
}

func parseConfig(data []byte) (uint8, []configAttribute, error) {
	if len(data) < 4 {
		return 0, nil, errors.New("configuration payload is truncated")
	}
	kind := data[0]
	data = data[4:]
	var attributes []configAttribute
	for len(data) != 0 {
		if len(data) < 4 {
			return 0, nil, errors.New("configuration attribute is truncated")
		}
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if length > len(data)-4 {
			return 0, nil, errors.New("invalid configuration attribute length")
		}
		attributes = append(attributes, configAttribute{
			typeID: binary.BigEndian.Uint16(data[:2]) & 0x7fff,
			value:  append([]byte(nil), data[4:4+length]...),
		})
		data = data[4+length:]
	}
	return kind, attributes, nil
}

func containsConfigAttribute(attributes []configAttribute, kind uint16) bool {
	for _, attribute := range attributes {
		if attribute.typeID == kind {
			return true
		}
	}
	return false
}
