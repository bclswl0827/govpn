package ikev2

import (
	"crypto/cipher"
	"crypto/des"  //nolint:gosec // DES is required by the MS-CHAPv2 wire format.
	"crypto/sha1" //nolint:gosec // SHA-1 is required by RFC 2759 and RFC 3079.
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is required for the NT password hash.
)

const (
	eapRequest  = 1
	eapResponse = 2
	eapSuccess  = 3
	eapFailure  = 4

	eapTypeIdentity = 1
	eapTypeMSCHAPv2 = 26

	mschapChallenge = 1
	mschapResponse  = 2
	mschapSuccess   = 3
	mschapFailure   = 4
)

type eapMessage struct {
	code       uint8
	identifier uint8
	typeID     uint8
	data       []byte
}

func parseEAP(value []byte) (eapMessage, error) {
	if len(value) < 4 || int(binary.BigEndian.Uint16(value[2:4])) != len(value) {
		return eapMessage{}, errors.New("invalid EAP packet length")
	}
	message := eapMessage{code: value[0], identifier: value[1]}
	switch message.code {
	case eapSuccess, eapFailure:
		if len(value) != 4 {
			return eapMessage{}, errors.New("invalid EAP success or failure packet")
		}
	case eapRequest, eapResponse:
		if len(value) < 5 {
			return eapMessage{}, errors.New("truncated EAP request or response")
		}
		message.typeID = value[4]
		message.data = append([]byte(nil), value[5:]...)
	default:
		return eapMessage{}, fmt.Errorf("unsupported EAP code %d", message.code)
	}
	return message, nil
}

func marshalEAP(code, identifier, typeID uint8, data []byte) []byte {
	length := 5 + len(data)
	value := make([]byte, length)
	value[0], value[1], value[4] = code, identifier, typeID
	binary.BigEndian.PutUint16(value[2:4], uint16(length))
	copy(value[5:], data)
	return value
}

func marshalEAPResult(code, identifier uint8) []byte {
	return []byte{code, identifier, 0, 4}
}

type eapClientState struct {
	username string
	password string
	msk      []byte
	expected string
}

func (state *eapClientState) handle(value []byte) ([]byte, bool, error) {
	message, err := parseEAP(value)
	if err != nil {
		return nil, false, err
	}
	switch message.code {
	case eapSuccess:
		if len(state.msk) != 64 {
			return nil, false, errors.New("EAP succeeded without MSCHAPv2 key material")
		}
		return nil, true, nil
	case eapFailure:
		return nil, false, errors.New("EAP-MSCHAPv2 authentication failed")
	case eapRequest:
	default:
		return nil, false, errors.New("responder sent an unexpected EAP response")
	}

	switch message.typeID {
	case eapTypeIdentity:
		return marshalEAP(eapResponse, message.identifier, eapTypeIdentity, []byte(state.username)), false, nil
	case eapTypeMSCHAPv2:
		if len(message.data) == 0 {
			return nil, false, errors.New("empty EAP-MSCHAPv2 request")
		}
		switch message.data[0] {
		case mschapChallenge:
			packet, expected, msk, err := answerMSCHAPChallenge(message, state.username, state.password)
			if err != nil {
				return nil, false, err
			}
			state.expected, state.msk = expected, msk
			return packet, false, nil
		case mschapSuccess:
			if state.expected == "" || !verifyMSCHAPSuccess(message.data, state.expected) {
				return nil, false, errors.New("EAP-MSCHAPv2 responder authenticator is invalid")
			}
			return marshalEAP(eapResponse, message.identifier, eapTypeMSCHAPv2, []byte{mschapSuccess}), false, nil
		case mschapFailure:
			return nil, false, errors.New("EAP-MSCHAPv2 credentials were rejected")
		default:
			return nil, false, fmt.Errorf("unsupported EAP-MSCHAPv2 opcode %d", message.data[0])
		}
	default:
		return nil, false, fmt.Errorf("responder selected unsupported EAP type %d", message.typeID)
	}
}

func answerMSCHAPChallenge(message eapMessage, username, password string) ([]byte, string, []byte, error) {
	data := message.data
	if len(data) < 22 || data[0] != mschapChallenge || data[4] != 16 ||
		int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
		return nil, "", nil, errors.New("invalid EAP-MSCHAPv2 challenge")
	}
	var authChallenge [16]byte
	copy(authChallenge[:], data[5:21])
	peerBytes, err := randomBytes(16)
	if err != nil {
		return nil, "", nil, err
	}
	var peerChallenge [16]byte
	copy(peerChallenge[:], peerBytes)
	bareUsername := mschapUsername(username)
	ntResponse := generateNTResponse(authChallenge, peerChallenge, bareUsername, password)
	expected := authenticatorResponse(authChallenge, peerChallenge, bareUsername, password, ntResponse)
	msk := generateMSCHAPMSK(password, ntResponse)

	responseData := make([]byte, 54+len(username))
	responseData[0] = mschapResponse
	responseData[1] = data[1]
	binary.BigEndian.PutUint16(responseData[2:4], uint16(len(responseData)))
	responseData[4] = 49
	copy(responseData[5:21], peerChallenge[:])
	copy(responseData[29:53], ntResponse[:])
	copy(responseData[54:], username)
	return marshalEAP(eapResponse, message.identifier, eapTypeMSCHAPv2, responseData), expected, msk, nil
}

func buildMSCHAPChallenge(identifier uint8, challenge [16]byte, name string) []byte {
	data := make([]byte, 21+len(name))
	data[0], data[1], data[4] = mschapChallenge, identifier, 16
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	copy(data[5:21], challenge[:])
	copy(data[21:], name)
	return marshalEAP(eapRequest, identifier, eapTypeMSCHAPv2, data)
}

type mschapResponseValue struct {
	username      string
	peerChallenge [16]byte
	ntResponse    [24]byte
}

func parseMSCHAPResponse(value []byte, identifier uint8) (mschapResponseValue, error) {
	message, err := parseEAP(value)
	if err != nil {
		return mschapResponseValue{}, err
	}
	data := message.data
	if message.code != eapResponse || message.identifier != identifier || message.typeID != eapTypeMSCHAPv2 ||
		len(data) < 55 || data[0] != mschapResponse || data[4] != 49 ||
		int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
		return mschapResponseValue{}, errors.New("invalid EAP-MSCHAPv2 response")
	}
	if data[1] != identifier || data[53] != 0 {
		return mschapResponseValue{}, errors.New("invalid EAP-MSCHAPv2 response flags")
	}
	result := mschapResponseValue{username: string(data[54:])}
	if result.username == "" {
		return mschapResponseValue{}, errors.New("EAP-MSCHAPv2 response omitted username")
	}
	copy(result.peerChallenge[:], data[5:21])
	copy(result.ntResponse[:], data[29:53])
	return result, nil
}

func buildMSCHAPSuccessRequest(identifier, mschapID uint8, authenticator string) []byte {
	message := authenticator + " M=Welcome2govpn"
	data := make([]byte, 4+len(message))
	data[0], data[1] = mschapSuccess, mschapID
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	copy(data[4:], message)
	return marshalEAP(eapRequest, identifier, eapTypeMSCHAPv2, data)
}

func isMSCHAPSuccessResponse(value []byte, identifier uint8) bool {
	message, err := parseEAP(value)
	return err == nil && message.code == eapResponse && message.identifier == identifier &&
		message.typeID == eapTypeMSCHAPv2 && len(message.data) == 1 && message.data[0] == mschapSuccess
}

func verifyMSCHAPSuccess(data []byte, expected string) bool {
	if len(data) < 46 || data[0] != mschapSuccess || int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
		return false
	}
	for _, field := range strings.Fields(string(data[4:])) {
		if strings.HasPrefix(strings.ToUpper(field), "S=") {
			actual := []byte(strings.ToUpper(field))
			want := []byte(strings.ToUpper(expected))
			return len(actual) == len(want) && subtle.ConstantTimeCompare(actual, want) == 1
		}
	}
	return false
}

func mschapUsername(value string) string {
	if index := strings.IndexByte(value, '\\'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func ntPasswordHash(password string) [16]byte {
	encoded := utf16.Encode([]rune(password))
	value := make([]byte, len(encoded)*2)
	for index, code := range encoded {
		binary.LittleEndian.PutUint16(value[index*2:], code)
	}
	hash := md4.New()
	_, _ = hash.Write(value)
	var result [16]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func hashNTHash(value [16]byte) [16]byte {
	hash := md4.New()
	_, _ = hash.Write(value[:])
	var result [16]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func challengeHash(peerChallenge, authChallenge [16]byte, username string) [8]byte {
	hash := sha1.New()
	_, _ = hash.Write(peerChallenge[:])
	_, _ = hash.Write(authChallenge[:])
	_, _ = hash.Write([]byte(username))
	var result [8]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func generateNTResponse(authChallenge, peerChallenge [16]byte, username, password string) [24]byte {
	challenge := challengeHash(peerChallenge, authChallenge, username)
	passwordHash := ntPasswordHash(password)
	var padded [21]byte
	copy(padded[:], passwordHash[:])
	var result [24]byte
	for index := 0; index < 3; index++ {
		block := desCipher(padded[index*7 : index*7+7])
		block.Encrypt(result[index*8:], challenge[:])
	}
	return result
}

func desCipher(key []byte) cipher.Block {
	var expanded [8]byte
	expanded[0] = key[0]
	expanded[1] = key[0]<<7 | key[1]>>1
	expanded[2] = key[1]<<6 | key[2]>>2
	expanded[3] = key[2]<<5 | key[3]>>3
	expanded[4] = key[3]<<4 | key[4]>>4
	expanded[5] = key[4]<<3 | key[5]>>5
	expanded[6] = key[5]<<2 | key[6]>>6
	expanded[7] = key[6] << 1
	block, err := des.NewCipher(expanded[:])
	if err != nil {
		panic("ikev2: invalid fixed-size DES key")
	}
	return block
}

func authenticatorResponse(authChallenge, peerChallenge [16]byte, username, password string, ntResponse [24]byte) string {
	passwordHashHash := hashNTHash(ntPasswordHash(password))
	hash := sha1.New()
	_, _ = hash.Write(passwordHashHash[:])
	_, _ = hash.Write(ntResponse[:])
	_, _ = hash.Write([]byte("Magic server to client signing constant"))
	digest := hash.Sum(nil)
	challenge := challengeHash(peerChallenge, authChallenge, username)
	hash.Reset()
	_, _ = hash.Write(digest)
	_, _ = hash.Write(challenge[:])
	_, _ = hash.Write([]byte("Pad to make it do more than one iteration"))
	return "S=" + strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
}

func generateMSCHAPMSK(password string, ntResponse [24]byte) []byte {
	passwordHashHash := hashNTHash(ntPasswordHash(password))
	hash := sha1.New()
	_, _ = hash.Write(passwordHashHash[:])
	_, _ = hash.Write(ntResponse[:])
	_, _ = hash.Write([]byte("This is the MPPE Master Key"))
	master := hash.Sum(nil)[:16]
	derive := func(magic string) []byte {
		hash.Reset()
		_, _ = hash.Write(master)
		_, _ = hash.Write(make([]byte, 40))
		_, _ = hash.Write([]byte(magic))
		_, _ = hash.Write([]byte(strings.Repeat("\xf2", 40)))
		return append([]byte(nil), hash.Sum(nil)[:16]...)
	}
	receive := derive("On the client side, this is the send key; on the server side, it is the receive key.")
	send := derive("On the client side, this is the receive key; on the server side, it is the send key.")
	msk := make([]byte, 64)
	copy(msk[0:16], receive)
	copy(msk[16:32], send)
	return msk
}
