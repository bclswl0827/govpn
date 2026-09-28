package ikev2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
)

const (
	prfKeyLen           = 32
	ikeEncryptionKeyLen = 32
	ikeIntegrityKeyLen  = 32
	ikeICVLen           = 16
	espEncryptionKeyLen = 32
	espIntegrityKeyLen  = 32
)

var modp2048Prime, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

var modp1024Prime, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF", 16)

type modpKey struct {
	private *big.Int
	prime   *big.Int
	size    int
}

func generateMODPKey(group uint16) (*modpKey, []byte, error) {
	var prime *big.Int
	var size int
	switch group {
	case dhMODP1024:
		prime, size = modp1024Prime, 128
	case dhMODP2048:
		prime, size = modp2048Prime, 256
	default:
		return nil, nil, fmt.Errorf("unsupported MODP group %d", group)
	}
	maximum := new(big.Int).Sub(prime, big.NewInt(3))
	private, err := rand.Int(rand.Reader, maximum)
	if err != nil {
		return nil, nil, err
	}
	private.Add(private, big.NewInt(2))
	public := new(big.Int).Exp(big.NewInt(2), private, prime)
	return &modpKey{private: private, prime: prime, size: size}, leftPad(public.Bytes(), size), nil
}

func (key *modpKey) secret(peerBytes []byte) ([]byte, error) {
	if key == nil || key.private == nil || key.prime == nil || len(peerBytes) != key.size {
		return nil, errors.New("invalid MODP key material")
	}
	peer := new(big.Int).SetBytes(peerBytes)
	upper := new(big.Int).Sub(key.prime, big.NewInt(1))
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(upper) >= 0 {
		return nil, errors.New("invalid MODP peer public value")
	}
	return leftPad(new(big.Int).Exp(peer, key.private, key.prime).Bytes(), key.size), nil
}

func leftPad(value []byte, length int) []byte {
	if len(value) >= length {
		return append([]byte(nil), value...)
	}
	result := make([]byte, length)
	copy(result[length-len(value):], value)
	return result
}

func randomBytes(length int) ([]byte, error) {
	result := make([]byte, length)
	if _, err := rand.Read(result); err != nil {
		return nil, err
	}
	return result, nil
}

func randomUint64() (uint64, error) {
	for {
		value, err := randomBytes(8)
		if err != nil {
			return 0, err
		}
		result := binary.BigEndian.Uint64(value)
		if result != 0 {
			return result, nil
		}
	}
}

func randomUint32() (uint32, error) {
	for {
		value, err := randomBytes(4)
		if err != nil {
			return 0, err
		}
		result := binary.BigEndian.Uint32(value)
		if result != 0 {
			return result, nil
		}
	}
}

func prf(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func prfPlus(key, seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(result) < length; counter++ {
		input := make([]byte, 0, len(previous)+len(seed)+1)
		input = append(input, previous...)
		input = append(input, seed...)
		input = append(input, counter)
		previous = prf(key, input)
		result = append(result, previous...)
	}
	return result[:length]
}

type ikeKeys struct {
	skD        []byte
	skAI, skAR []byte
	skEI, skER []byte
	skPI, skPR []byte
}

func deriveIKEKeys(ni, nr, shared []byte, initiatorSPI, responderSPI uint64) ikeKeys {
	nonces := append(append([]byte(nil), ni...), nr...)
	skeyseed := prf(nonces, shared)
	seed := append([]byte(nil), nonces...)
	var spis [16]byte
	binary.BigEndian.PutUint64(spis[:8], initiatorSPI)
	binary.BigEndian.PutUint64(spis[8:], responderSPI)
	seed = append(seed, spis[:]...)
	const total = prfKeyLen + 2*ikeIntegrityKeyLen + 2*ikeEncryptionKeyLen + 2*prfKeyLen
	material := prfPlus(skeyseed, seed, total)
	take := func(length int) []byte {
		value := append([]byte(nil), material[:length]...)
		material = material[length:]
		return value
	}
	return ikeKeys{
		skD: take(prfKeyLen), skAI: take(ikeIntegrityKeyLen), skAR: take(ikeIntegrityKeyLen),
		skEI: take(ikeEncryptionKeyLen), skER: take(ikeEncryptionKeyLen),
		skPI: take(prfKeyLen), skPR: take(prfKeyLen),
	}
}

func (keys ikeKeys) encryptionKey(fromInitiator bool) []byte {
	if fromInitiator {
		return keys.skEI
	}
	return keys.skER
}

func (keys ikeKeys) integrityKey(fromInitiator bool) []byte {
	if fromInitiator {
		return keys.skAI
	}
	return keys.skAR
}

func encryptMessage(h ikeHeader, inner []payload, keys ikeKeys, fromInitiator bool) ([]byte, error) {
	first, plaintext, err := marshalPayloads(inner)
	if err != nil {
		return nil, err
	}
	paddingLength := (aes.BlockSize - (len(plaintext)+1)%aes.BlockSize) % aes.BlockSize
	for index := 0; index < paddingLength; index++ {
		plaintext = append(plaintext, byte(index+1))
	}
	plaintext = append(plaintext, byte(paddingLength))
	block, err := aes.NewCipher(keys.encryptionKey(fromInitiator))
	if err != nil {
		return nil, err
	}
	iv, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	skLength := 4 + len(iv) + len(ciphertext) + ikeICVLen
	h.nextPayload = payloadSK
	raw := marshalIKEHeader(h, ikeHeaderLen+skLength)
	skHeader := make([]byte, 4)
	skHeader[0] = first
	binary.BigEndian.PutUint16(skHeader[2:4], uint16(skLength))
	raw = append(raw, skHeader...)
	raw = append(raw, iv...)
	raw = append(raw, ciphertext...)
	mac := hmac.New(sha256.New, keys.integrityKey(fromInitiator))
	_, _ = mac.Write(raw)
	return append(raw, mac.Sum(nil)[:ikeICVLen]...), nil
}

func decryptMessage(raw []byte, keys ikeKeys, fromInitiator bool) (ikeHeader, []payload, error) {
	h, err := parseIKEHeader(raw)
	if err != nil {
		return ikeHeader{}, nil, err
	}
	if h.nextPayload != payloadSK || len(raw) < ikeHeaderLen+4+aes.BlockSize+aes.BlockSize+ikeICVLen {
		return ikeHeader{}, nil, errors.New("missing or truncated encrypted payload")
	}
	skLength := int(binary.BigEndian.Uint16(raw[ikeHeaderLen+2 : ikeHeaderLen+4]))
	if skLength != len(raw)-ikeHeaderLen {
		return ikeHeader{}, nil, errors.New("invalid encrypted payload length")
	}
	messageEnd := len(raw) - ikeICVLen
	mac := hmac.New(sha256.New, keys.integrityKey(fromInitiator))
	_, _ = mac.Write(raw[:messageEnd])
	if subtle.ConstantTimeCompare(mac.Sum(nil)[:ikeICVLen], raw[messageEnd:]) != 1 {
		return ikeHeader{}, nil, errors.New("IKE integrity check failed")
	}
	ivStart := ikeHeaderLen + 4
	iv := raw[ivStart : ivStart+aes.BlockSize]
	ciphertext := raw[ivStart+aes.BlockSize : messageEnd]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return ikeHeader{}, nil, errors.New("invalid IKE ciphertext length")
	}
	block, err := aes.NewCipher(keys.encryptionKey(fromInitiator))
	if err != nil {
		return ikeHeader{}, nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	paddingLength := int(plaintext[len(plaintext)-1])
	if paddingLength+1 > len(plaintext) {
		return ikeHeader{}, nil, errors.New("invalid IKE padding")
	}
	plaintext = plaintext[:len(plaintext)-paddingLength-1]
	payloads, err := parsePayloads(raw[ikeHeaderLen], plaintext)
	if err != nil {
		return ikeHeader{}, nil, err
	}
	for _, item := range payloads {
		if item.critical && !knownPayload(item.typeID) {
			return ikeHeader{}, nil, fmt.Errorf("unsupported critical payload %d", item.typeID)
		}
	}
	return h, payloads, nil
}

func knownPayload(kind uint8) bool {
	switch kind {
	case payloadSA, payloadKE, payloadIDi, payloadIDr, payloadCERT, payloadCERTReq,
		payloadAUTH, payloadNonce, payloadNotify, payloadDelete, payloadTSi,
		payloadTSr, payloadCP, payloadEAP:
		return true
	default:
		return false
	}
}

func signedOctets(initMessage, peerNonce, skP, idBody []byte) []byte {
	signed := make([]byte, 0, len(initMessage)+len(peerNonce)+sha256.Size)
	signed = append(signed, initMessage...)
	signed = append(signed, peerNonce...)
	signed = append(signed, prf(skP, idBody)...)
	return signed
}

func authenticationValue(secret, initMessage, peerNonce, skP, idBody []byte) []byte {
	key := prf(secret, []byte("Key Pad for IKEv2"))
	return prf(key, signedOctets(initMessage, peerNonce, skP, idBody))
}

func secretEqual(left, right []byte) bool {
	return subtle.ConstantTimeCompare(left, right) == 1
}

func natDetectionHash(initiatorSPI, responderSPI uint64, ip net.IP, port int) []byte {
	value := make([]byte, 0, 16+net.IPv4len+2)
	var spis [16]byte
	binary.BigEndian.PutUint64(spis[:8], initiatorSPI)
	binary.BigEndian.PutUint64(spis[8:], responderSPI)
	value = append(value, spis[:]...)
	value = append(value, ip.To4()...)
	var encodedPort [2]byte
	binary.BigEndian.PutUint16(encodedPort[:], uint16(port))
	value = append(value, encodedPort[:]...)
	digest := sha1.Sum(value)
	return digest[:]
}

func detectsNAT(payloads []payload, source, destination []byte) bool {
	sourceMatched, destinationMatched := false, false
	sourceSeen, destinationSeen := false, false
	for _, item := range payloads {
		kind, data, ok := notifyType(item)
		if !ok {
			continue
		}
		switch kind {
		case notifyNATSource:
			sourceSeen = true
			sourceMatched = sourceMatched || hmac.Equal(data, source)
		case notifyNATDestination:
			destinationSeen = true
			destinationMatched = destinationMatched || hmac.Equal(data, destination)
		}
	}
	return (sourceSeen && !sourceMatched) || (destinationSeen && !destinationMatched)
}

type espKeyMaterial struct {
	i2rEncryption, i2rIntegrity []byte
	r2iEncryption, r2iIntegrity []byte
}

func deriveESPKeys(keys ikeKeys, ni, nr []byte) espKeyMaterial {
	seed := append(append([]byte(nil), ni...), nr...)
	material := prfPlus(keys.skD, seed, 2*(espEncryptionKeyLen+espIntegrityKeyLen))
	take := func(length int) []byte {
		value := append([]byte(nil), material[:length]...)
		material = material[length:]
		return value
	}
	return espKeyMaterial{
		i2rEncryption: take(espEncryptionKeyLen), i2rIntegrity: take(espIntegrityKeyLen),
		r2iEncryption: take(espEncryptionKeyLen), r2iIntegrity: take(espIntegrityKeyLen),
	}
}
