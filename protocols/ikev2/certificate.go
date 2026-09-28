package ikev2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // IKEv2 RSA method 1 requires SHA-1.
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func parseCertificates(value []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	rest := value
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		parsed, err := x509.ParseCertificates(value)
		if err != nil {
			return nil, errors.New("no valid X.509 certificates found")
		}
		certificates = parsed
	}
	return certificates, nil
}

func parseRSAPrivateKey(value []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, errors.New("no PEM private key found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key is neither PKCS#1 nor PKCS#8")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func signRSAAuthentication(key *rsa.PrivateKey, signed []byte) ([]byte, error) {
	digest := sha1.Sum(signed)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
}

func verifyRSAAuthentication(certificate *x509.Certificate, signed, signature []byte) error {
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("responder certificate does not contain an RSA key")
	}
	digest := sha1.Sum(signed)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest[:], signature); err != nil {
		return errors.New("responder IKE AUTH signature is invalid")
	}
	return nil
}

func certificatesFromPayloads(payloads []payload) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for _, item := range payloads {
		if item.typeID != payloadCERT {
			continue
		}
		if len(item.data) < 2 || item.data[0] != 4 {
			return nil, errors.New("unsupported responder certificate encoding")
		}
		certificate, err := x509.ParseCertificate(item.data[1:])
		if err != nil {
			return nil, fmt.Errorf("invalid responder certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, errors.New("IKE_AUTH response omitted responder certificate")
	}
	return certificates, nil
}

func verifyCertificateChain(certificates []*x509.Certificate, roots *x509.CertPool, serverName string) error {
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := certificates[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: serverName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("responder certificate verification failed: %w", err)
	}
	return nil
}
