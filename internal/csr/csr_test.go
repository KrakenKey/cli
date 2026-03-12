package csr_test

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/krakenkey/cli/internal/csr"
)

func TestGenerate_AllKeyTypes(t *testing.T) {
	types := []struct {
		keyType     string
		wantKeyType string
		wantSize    int
	}{
		{csr.KeyTypeRSA2048, "RSA", 2048},
		{csr.KeyTypeRSA4096, "RSA", 4096},
		{csr.KeyTypeECDSAP256, "ECDSA", 256},
		{csr.KeyTypeECDSAP384, "ECDSA", 384},
	}

	for _, tc := range types {
		t.Run(tc.keyType, func(t *testing.T) {
			result, err := csr.Generate(tc.keyType, csr.Subject{CommonName: "example.com"}, nil)
			if err != nil {
				t.Fatalf("Generate(%q): unexpected error: %v", tc.keyType, err)
			}
			if result.KeyType != tc.wantKeyType {
				t.Errorf("KeyType = %q, want %q", result.KeyType, tc.wantKeyType)
			}
			if result.KeySize != tc.wantSize {
				t.Errorf("KeySize = %d, want %d", result.KeySize, tc.wantSize)
			}
			if len(result.CSRPem) == 0 {
				t.Error("CSRPem is empty")
			}
			if len(result.PrivateKeyPem) == 0 {
				t.Error("PrivateKeyPem is empty")
			}
		})
	}
}

func TestGenerate_CSRIsValid(t *testing.T) {
	subject := csr.Subject{
		CommonName:         "example.com",
		Organization:       "Acme Inc",
		OrganizationalUnit: "Engineering",
		Locality:           "San Francisco",
		State:              "CA",
		Country:            "US",
	}
	sans := []string{"www.example.com", "api.example.com"}

	result, err := csr.Generate(csr.KeyTypeECDSAP256, subject, sans)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the CSR PEM.
	block, _ := pem.Decode(result.CSRPem)
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("PEM type = %q, want CERTIFICATE REQUEST", block.Type)
	}

	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}

	if parsed.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want example.com", parsed.Subject.CommonName)
	}
	if len(parsed.Subject.Organization) == 0 || parsed.Subject.Organization[0] != "Acme Inc" {
		t.Errorf("O = %v, want [Acme Inc]", parsed.Subject.Organization)
	}
}

func TestGenerate_CNIncludedInDNSNames(t *testing.T) {
	result, err := csr.Generate(csr.KeyTypeECDSAP256, csr.Subject{CommonName: "example.com"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(result.CSRPem)
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	found := false
	for _, name := range parsed.DNSNames {
		if name == "example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("CN not found in DNSNames: %v", parsed.DNSNames)
	}
}

func TestGenerate_DeduplicatesSANs(t *testing.T) {
	// CN + duplicate SAN should only appear once.
	result, err := csr.Generate(csr.KeyTypeECDSAP256, csr.Subject{CommonName: "example.com"}, []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(result.CSRPem)
	parsed, _ := x509.ParseCertificateRequest(block.Bytes)

	count := 0
	for _, name := range parsed.DNSNames {
		if name == "example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("example.com appears %d times in DNSNames, want 1", count)
	}
}

func TestGenerate_IPSANs(t *testing.T) {
	result, err := csr.Generate(csr.KeyTypeECDSAP256, csr.Subject{CommonName: "example.com"}, []string{"192.168.1.1", "::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(result.CSRPem)
	parsed, _ := x509.ParseCertificateRequest(block.Bytes)

	if len(parsed.IPAddresses) != 2 {
		t.Errorf("IPAddresses count = %d, want 2", len(parsed.IPAddresses))
	}
	wantIPs := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")}
	for i, ip := range wantIPs {
		if i >= len(parsed.IPAddresses) {
			break
		}
		if !parsed.IPAddresses[i].Equal(ip) {
			t.Errorf("IPAddresses[%d] = %v, want %v", i, parsed.IPAddresses[i], ip)
		}
	}
}

func TestGenerate_PrivateKeyIsPKCS8(t *testing.T) {
	result, err := csr.Generate(csr.KeyTypeRSA2048, csr.Subject{CommonName: "example.com"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(result.PrivateKeyPem)
	if block == nil {
		t.Fatal("failed to decode private key PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM type = %q, want PRIVATE KEY", block.Type)
	}

	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("ParsePKCS8PrivateKey: %v", err)
	}
}

func TestGenerate_InvalidKeyType(t *testing.T) {
	_, err := csr.Generate("rsa-1024", csr.Subject{CommonName: "example.com"}, nil)
	if err == nil {
		t.Error("expected error for invalid key type, got nil")
	}
}
