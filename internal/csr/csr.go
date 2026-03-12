// Package csr handles local CSR and private key generation.
// Private keys are generated in-process and never transmitted to the API.
package csr

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
	panic("not implemented")
}
