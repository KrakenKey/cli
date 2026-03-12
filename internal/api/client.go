package api

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client handles HTTP communication with the KrakenKey API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	userAgent  string
}

// NewClient creates a new API client.
// version, goos, and goarch are used to build the User-Agent header.
func NewClient(baseURL, apiKey, version, goos, goarch string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: fmt.Sprintf("krakenkey-cli/%s (%s/%s)", version, goos, goarch),
	}
}

// Domain methods

func (c *Client) CreateDomain(ctx context.Context, hostname string) (*Domain, error) {
	panic("not implemented")
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	panic("not implemented")
}

func (c *Client) GetDomain(ctx context.Context, id string) (*Domain, error) {
	panic("not implemented")
}

func (c *Client) VerifyDomain(ctx context.Context, id string) (*Domain, error) {
	panic("not implemented")
}

func (c *Client) DeleteDomain(ctx context.Context, id string) error {
	panic("not implemented")
}

// Certificate methods

func (c *Client) CreateCert(ctx context.Context, csrPem string) (*CertResponse, error) {
	panic("not implemented")
}

func (c *Client) ListCerts(ctx context.Context, status string) ([]TlsCert, error) {
	panic("not implemented")
}

func (c *Client) GetCert(ctx context.Context, id int) (*TlsCert, error) {
	panic("not implemented")
}

func (c *Client) GetCertDetails(ctx context.Context, id int) (*TlsCertDetails, error) {
	panic("not implemented")
}

func (c *Client) UpdateCert(ctx context.Context, id int, autoRenew *bool) (*TlsCert, error) {
	panic("not implemented")
}

func (c *Client) RenewCert(ctx context.Context, id int) (*CertResponse, error) {
	panic("not implemented")
}

func (c *Client) RevokeCert(ctx context.Context, id int, reason *int) (*CertResponse, error) {
	panic("not implemented")
}

func (c *Client) RetryCert(ctx context.Context, id int) (*CertResponse, error) {
	panic("not implemented")
}

func (c *Client) DeleteCert(ctx context.Context, id int) error {
	panic("not implemented")
}

// Auth methods

func (c *Client) GetProfile(ctx context.Context) (*UserProfile, error) {
	panic("not implemented")
}

func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	panic("not implemented")
}

func (c *Client) CreateAPIKey(ctx context.Context, name string, expiresAt *string) (*CreateAPIKeyResponse, error) {
	panic("not implemented")
}

func (c *Client) DeleteAPIKey(ctx context.Context, id string) error {
	panic("not implemented")
}

// Billing methods

func (c *Client) GetSubscription(ctx context.Context) (*Subscription, error) {
	panic("not implemented")
}
