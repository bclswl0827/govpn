package ikev2

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestMSCHAPv2RFCVectors(t *testing.T) {
	decode := func(value string) []byte {
		result, err := hex.DecodeString(strings.ReplaceAll(value, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	var authenticatorChallenge, peerChallenge [16]byte
	copy(authenticatorChallenge[:], decode("5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28"))
	copy(peerChallenge[:], decode("21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E"))

	response := generateNTResponse(authenticatorChallenge, peerChallenge, "User", "clientPass")
	wantResponse := "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"
	if got := strings.ToUpper(hex.EncodeToString(response[:])); got != wantResponse {
		t.Fatalf("NT-Response = %s, want %s", got, wantResponse)
	}
	if got, want := authenticatorResponse(authenticatorChallenge, peerChallenge, "User", "clientPass", response),
		"S=407A5589115FD0D6209F510FE9C04566932CDA56"; got != want {
		t.Fatalf("AuthenticatorResponse = %s, want %s", got, want)
	}
	msk := generateMSCHAPMSK("clientPass", response)
	// EAP-MSCHAPv2 places the authenticator receive key first and its send
	// key second, matching StrongSwan's GenerateMSK() and the RADIUS MPPE key
	// ordering. RFC 3079's 8B7C... sample is the send key, not MSK[0:16].
	wantReceiveKey := "D5F0E9521E3EA9589645E86051C82226"
	if got := strings.ToUpper(hex.EncodeToString(msk[:16])); got != wantReceiveKey {
		t.Fatalf("MSK receive key = %s, want %s", got, wantReceiveKey)
	}
	wantSendKey := "8B7CDC149B993A1BA118CB153F56DCCB"
	if got := strings.ToUpper(hex.EncodeToString(msk[16:32])); got != wantSendKey {
		t.Fatalf("MSK send key = %s, want %s", got, wantSendKey)
	}
}
