// Package csr handles local CSR and private key generation.
// Private keys are generated in-process and never transmitted to the API.
package csr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
)

// Supported key types.
const (
	KeyTypeRSA2048   = "rsa-2048"
	KeyTypeRSA4096   = "rsa-4096"
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeECDSAP384 = "ecdsa-p384"
)

// Subject holds the CSR subject fields.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Locality           string
	State              string
	Country            string
}

// Result holds the generated CSR and private key.
type Result struct {
	CSRPem        []byte // PEM-encoded CERTIFICATE REQUEST
	PrivateKeyPem []byte // PEM-encoded PKCS#8 PRIVATE KEY
	KeyType       string // "RSA" or "ECDSA"
	KeySize       int    // 2048, 4096, 256, or 384
}

// Generate creates a private key and CSR for the given key type, subject, and SANs.
// The CN is automatically added to DNSNames. IP SANs are detected and placed in IPAddresses.
// The private key is encoded as PKCS#8 PEM.
func Generate(keyType string, subject Subject, sans []string) (*Result, error) {
	var (
		privKey     any
		resultType  string
		resultSize  int
	)

	switch keyType {
	case KeyTypeRSA2048:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA-2048 key: %w", err)
		}
		privKey, resultType, resultSize = k, "RSA", 2048
	case KeyTypeRSA4096:
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("generate RSA-4096 key: %w", err)
		}
		privKey, resultType, resultSize = k, "RSA", 4096
	case KeyTypeECDSAP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA P-256 key: %w", err)
		}
		privKey, resultType, resultSize = k, "ECDSA", 256
	case KeyTypeECDSAP384:
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA P-384 key: %w", err)
		}
		privKey, resultType, resultSize = k, "ECDSA", 384
	default:
		return nil, fmt.Errorf("unsupported key type %q — use rsa-2048, rsa-4096, ecdsa-p256, or ecdsa-p384", keyType)
	}

	pkixSubject := pkix.Name{CommonName: subject.CommonName}
	if subject.Organization != "" {
		pkixSubject.Organization = []string{subject.Organization}
	}
	if subject.OrganizationalUnit != "" {
		pkixSubject.OrganizationalUnit = []string{subject.OrganizationalUnit}
	}
	if subject.Locality != "" {
		pkixSubject.Locality = []string{subject.Locality}
	}
	if subject.State != "" {
		pkixSubject.Province = []string{subject.State}
	}
	if subject.Country != "" {
		pkixSubject.Country = []string{subject.Country}
	}

	// CN is always included in SANs; dedup across CN + extra SANs.
	var dnsNames []string
	var ipAddresses []net.IP
	seen := map[string]bool{}
	for _, san := range append([]string{subject.CommonName}, sans...) {
		if san == "" || seen[san] {
			continue
		}
		seen[san] = true
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	template := &x509.CertificateRequest{
		Subject:     pkixSubject,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	privKeyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyDER})

	return &Result{
		CSRPem:        csrPem,
		PrivateKeyPem: privKeyPem,
		KeyType:       resultType,
		KeySize:       resultSize,
	}, nil
}
