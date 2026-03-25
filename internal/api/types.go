// Package api provides the HTTP client and types for the KrakenKey REST API.
package api

import "time"

// Certificate status values.
const (
	CertStatusPending  = "pending"
	CertStatusIssuing  = "issuing"
	CertStatusIssued   = "issued"
	CertStatusFailed   = "failed"
	CertStatusRenewing = "renewing"
	CertStatusRevoking = "revoking"
	CertStatusRevoked  = "revoked"
)

// Domain represents a registered domain.
type Domain struct {
	ID               string    `json:"id"`
	Hostname         string    `json:"hostname"`
	VerificationCode string    `json:"verificationCode"`
	IsVerified       bool      `json:"isVerified"`
	CreatedAt        time.Time `json:"createdAt"`
}

// TlsCert represents a TLS certificate record.
type TlsCert struct {
	ID            int        `json:"id"`
	RawCsr        string     `json:"rawCsr"`
	ParsedCsr     *ParsedCsr `json:"parsedCsr"`
	CrtPem        string     `json:"crtPem"`
	Status        string     `json:"status"`
	ExpiresAt     *time.Time `json:"expiresAt"`
	LastRenewedAt *time.Time `json:"lastRenewedAt"`
	AutoRenew     bool       `json:"autoRenew"`
	RenewalCount  int        `json:"renewalCount"`
	CreatedAt     time.Time  `json:"createdAt"`
	UserID        string     `json:"userId"`
}

// ParsedCsr is the server-parsed representation of the submitted CSR.
type ParsedCsr struct {
	Subject    []CsrSubjectField `json:"subject"`
	PublicKey  *CsrPublicKey     `json:"publicKey"`
	Extensions []CsrExtension    `json:"extensions"`
}

// CsrSubjectField is a single subject RDN (e.g. commonName, organization).
type CsrSubjectField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CsrPublicKey describes the public key embedded in the CSR.
type CsrPublicKey struct {
	KeyType   string `json:"keyType"`
	BitLength int    `json:"bitLength"`
}

// CsrExtension holds parsed certificate extensions (e.g. SANs).
type CsrExtension struct {
	AltNames []AltName `json:"altNames"`
}

// AltName is a Subject Alternative Name entry.
// Type 2 = dNSName, Type 7 = iPAddress.
type AltName struct {
	Type  int    `json:"type"`
	Value string `json:"value"`
}

// TlsCertDetails holds parsed details of an issued certificate.
// Only available for certs with status "issued".
type TlsCertDetails struct {
	SerialNumber string    `json:"serialNumber"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidTo      time.Time `json:"validTo"`
	KeyType      string    `json:"keyType"`
	KeySize      int       `json:"keySize"`
	Fingerprint  string    `json:"fingerprint"`
}

// CertResponse is returned by mutating cert operations (create, renew, revoke, retry).
type CertResponse struct {
	ID     int    `json:"id"`
	Status string `json:"status"`
}

// UserProfile is the authenticated user's profile.
type UserProfile struct {
	ID             string         `json:"id"`
	Username       string         `json:"username"`
	Email          string         `json:"email"`
	DisplayName    string         `json:"displayName"`
	Plan           string         `json:"plan"`
	CreatedAt      time.Time      `json:"createdAt"`
	ResourceCounts ResourceCounts `json:"resourceCounts"`
}

// ResourceCounts holds current usage counts for a user.
type ResourceCounts struct {
	Domains      int `json:"domains"`
	Certificates int `json:"certificates"`
	APIKeys      int `json:"apiKeys"`
}

// APIKey represents a stored API key (secret not included after creation).
type APIKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

// CreateAPIKeyResponse is returned when a new API key is created.
// The APIKey field contains the full secret — only shown once.
type CreateAPIKeyResponse struct {
	APIKey string `json:"apiKey"`
	ID     string `json:"id"`
	Name   string `json:"name"`
}

// Subscription represents the user's billing subscription.
type Subscription struct {
	Plan              string     `json:"plan"`
	Status            string     `json:"status"`
	CurrentPeriodEnd  *time.Time `json:"currentPeriodEnd"`
	CancelAtPeriodEnd bool       `json:"cancelAtPeriodEnd"`
	CreatedAt         time.Time  `json:"createdAt"`
}

// Endpoint represents a monitored endpoint.
type Endpoint struct {
	ID            string                `json:"id"`
	UserID        string                `json:"userId"`
	Host          string                `json:"host"`
	Port          int                   `json:"port"`
	SNI           *string               `json:"sni"`
	Label         *string               `json:"label"`
	IsActive      bool                  `json:"isActive"`
	HostedRegions []EndpointHostedRegion `json:"hostedRegions"`
	CreatedAt     time.Time             `json:"createdAt"`
	UpdatedAt     time.Time             `json:"updatedAt"`
}

// EndpointHostedRegion links an endpoint to a hosted probe region.
type EndpointHostedRegion struct {
	ID         string    `json:"id"`
	EndpointID string    `json:"endpointId"`
	Region     string    `json:"region"`
	CreatedAt  time.Time `json:"createdAt"`
}

// APIError is the error shape returned by the KrakenKey API.
type APIError struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
	ErrorText  string `json:"error"`
	Timestamp  string `json:"timestamp"`
	Path       string `json:"path"`
	Limit      *int   `json:"limit,omitempty"`
	Current    *int   `json:"current,omitempty"`
	Plan       string `json:"plan,omitempty"`
}

func (e *APIError) Error() string { return e.Message }

// Typed errors allow main.go to map errors to specific exit codes.

// ErrAuth indicates an authentication failure (HTTP 401).
type ErrAuth struct{ Message string }

// ErrNotFound indicates the requested resource does not exist (HTTP 404).
type ErrNotFound struct{ Message string }

// ErrRateLimit indicates the request was rate-limited (HTTP 429).
type ErrRateLimit struct {
	Message    string
	RetryAfter string
}

// ErrConfig indicates a client-side configuration problem.
type ErrConfig struct{ Message string }

// ErrNetwork indicates a network-level failure (no response from server).
type ErrNetwork struct{ Message string }

func (e *ErrAuth) Error() string      { return e.Message }
func (e *ErrNotFound) Error() string  { return e.Message }
func (e *ErrRateLimit) Error() string { return e.Message }
func (e *ErrConfig) Error() string    { return e.Message }
func (e *ErrNetwork) Error() string   { return e.Message }
