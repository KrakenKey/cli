package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

// do executes an HTTP request and decodes the JSON response into out.
// If out is nil the response body is discarded. A non-2xx status code is
// decoded as an APIError and mapped to a typed error where appropriate.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return &ErrNetwork{Message: fmt.Sprintf("build request: %s", err)}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &ErrNetwork{Message: fmt.Sprintf("request failed: %s", err)}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ErrNetwork{Message: fmt.Sprintf("read response body: %s", err)}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIError
		if jsonErr := json.Unmarshal(respData, &apiErr); jsonErr != nil {
			apiErr = APIError{StatusCode: resp.StatusCode, Message: string(respData)}
		}
		apiErr.StatusCode = resp.StatusCode
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return &ErrAuth{Message: apiErr.Message}
		case http.StatusNotFound:
			return &ErrNotFound{Message: apiErr.Message}
		case http.StatusTooManyRequests:
			return &ErrRateLimit{
				Message:    apiErr.Message,
				RetryAfter: resp.Header.Get("Retry-After"),
			}
		default:
			return &apiErr
		}
	}

	if out != nil && len(respData) > 0 {
		if err := json.Unmarshal(respData, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Domain methods

func (c *Client) CreateDomain(ctx context.Context, hostname string) (*Domain, error) {
	body := map[string]string{"hostname": hostname}
	var d Domain
	if err := c.do(ctx, http.MethodPost, "/domains", body, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	var domains []Domain
	if err := c.do(ctx, http.MethodGet, "/domains", nil, &domains); err != nil {
		return nil, err
	}
	return domains, nil
}

func (c *Client) GetDomain(ctx context.Context, id string) (*Domain, error) {
	var d Domain
	if err := c.do(ctx, http.MethodGet, "/domains/"+id, nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (c *Client) VerifyDomain(ctx context.Context, id string) (*Domain, error) {
	var d Domain
	if err := c.do(ctx, http.MethodPost, "/domains/"+id+"/verify", nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (c *Client) DeleteDomain(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/domains/"+id, nil, nil)
}

// Certificate methods

func (c *Client) CreateCert(ctx context.Context, csrPem string) (*CertResponse, error) {
	body := map[string]string{"rawCsr": csrPem}
	var cr CertResponse
	if err := c.do(ctx, http.MethodPost, "/certs", body, &cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

func (c *Client) ListCerts(ctx context.Context, status string) ([]TlsCert, error) {
	path := "/certs"
	if status != "" {
		path += "?status=" + url.QueryEscape(status)
	}
	var certs []TlsCert
	if err := c.do(ctx, http.MethodGet, path, nil, &certs); err != nil {
		return nil, err
	}
	return certs, nil
}

func (c *Client) GetCert(ctx context.Context, id int) (*TlsCert, error) {
	var cert TlsCert
	if err := c.do(ctx, http.MethodGet, "/certs/"+strconv.Itoa(id), nil, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func (c *Client) GetCertDetails(ctx context.Context, id int) (*TlsCertDetails, error) {
	var details TlsCertDetails
	if err := c.do(ctx, http.MethodGet, "/certs/"+strconv.Itoa(id)+"/details", nil, &details); err != nil {
		return nil, err
	}
	return &details, nil
}

func (c *Client) UpdateCert(ctx context.Context, id int, autoRenew *bool) (*TlsCert, error) {
	body := map[string]any{"autoRenew": autoRenew}
	var cert TlsCert
	if err := c.do(ctx, http.MethodPatch, "/certs/"+strconv.Itoa(id), body, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func (c *Client) RenewCert(ctx context.Context, id int) (*CertResponse, error) {
	var cr CertResponse
	if err := c.do(ctx, http.MethodPost, "/certs/"+strconv.Itoa(id)+"/renew", nil, &cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

func (c *Client) RevokeCert(ctx context.Context, id int, reason *int) (*CertResponse, error) {
	var body any
	if reason != nil {
		body = map[string]int{"reason": *reason}
	}
	var cr CertResponse
	if err := c.do(ctx, http.MethodPost, "/certs/"+strconv.Itoa(id)+"/revoke", body, &cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

func (c *Client) RetryCert(ctx context.Context, id int) (*CertResponse, error) {
	var cr CertResponse
	if err := c.do(ctx, http.MethodPost, "/certs/"+strconv.Itoa(id)+"/retry", nil, &cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

func (c *Client) DeleteCert(ctx context.Context, id int) error {
	return c.do(ctx, http.MethodDelete, "/certs/"+strconv.Itoa(id), nil, nil)
}

// Auth methods

func (c *Client) GetProfile(ctx context.Context) (*UserProfile, error) {
	var p UserProfile
	if err := c.do(ctx, http.MethodGet, "/auth/me", nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var keys []APIKey
	if err := c.do(ctx, http.MethodGet, "/auth/api-keys", nil, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (c *Client) CreateAPIKey(ctx context.Context, name string, expiresAt *string) (*CreateAPIKeyResponse, error) {
	body := map[string]any{"name": name}
	if expiresAt != nil {
		body["expiresAt"] = *expiresAt
	}
	var resp CreateAPIKeyResponse
	if err := c.do(ctx, http.MethodPost, "/auth/api-keys", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) DeleteAPIKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/auth/api-keys/"+id, nil, nil)
}

// Billing methods

func (c *Client) GetSubscription(ctx context.Context) (*Subscription, error) {
	var s Subscription
	if err := c.do(ctx, http.MethodGet, "/billing/subscription", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
