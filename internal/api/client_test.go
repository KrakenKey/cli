package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/krakenkey/cli/internal/api"
)

// newTestClient creates a Client pointed at the given test server.
func newTestClient(baseURL string) *api.Client {
	return api.NewClient(baseURL, "kk_test", "v0.0.0", "linux", "amd64")
}

func TestNewClient_UserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.UserProfile{ID: "u1"})
	}))
	defer srv.Close()

	c := api.NewClient(srv.URL, "kk_test", "v1.2.3", "darwin", "arm64")
	_, _ = c.GetProfile(context.Background())

	want := "krakenkey-cli/v1.2.3 (darwin/arm64)"
	if gotUA != want {
		t.Errorf("User-Agent = %q, want %q", gotUA, want)
	}
}

func TestNewClient_AuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.UserProfile{})
	}))
	defer srv.Close()

	c := api.NewClient(srv.URL, "kk_supersecret", "dev", "linux", "amd64")
	_, _ = c.GetProfile(context.Background())

	if gotAuth != "Bearer kk_supersecret" {
		t.Errorf("Authorization = %q, want Bearer kk_supersecret", gotAuth)
	}
}

func TestClient_401_ReturnsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(api.APIError{StatusCode: 401, Message: "Unauthorized"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.GetProfile(context.Background())
	if _, ok := err.(*api.ErrAuth); !ok {
		t.Errorf("err type = %T, want *api.ErrAuth", err)
	}
}

func TestClient_404_ReturnsErrNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(api.APIError{StatusCode: 404, Message: "Not found"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.GetDomain(context.Background(), "nonexistent-id")
	if _, ok := err.(*api.ErrNotFound); !ok {
		t.Errorf("err type = %T, want *api.ErrNotFound", err)
	}
}

func TestClient_429_ReturnsErrRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(api.APIError{StatusCode: 429, Message: "Too many requests"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.ListCerts(context.Background(), "")
	rl, ok := err.(*api.ErrRateLimit)
	if !ok {
		t.Fatalf("err type = %T, want *api.ErrRateLimit", err)
	}
	if rl.RetryAfter != "30" {
		t.Errorf("RetryAfter = %q, want 30", rl.RetryAfter)
	}
}

func TestClient_GetProfile_Success(t *testing.T) {
	want := api.UserProfile{
		ID:          "user-123",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Plan:        "pro",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/profile" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	got, err := c.GetProfile(context.Background())
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.ID != want.ID || got.DisplayName != want.DisplayName || got.Email != want.Email {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestClient_CreateDomain_PostsJSON(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.Domain{ID: "d1", Hostname: "example.com"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	d, err := c.CreateDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if gotBody["hostname"] != "example.com" {
		t.Errorf("request body hostname = %q, want example.com", gotBody["hostname"])
	}
	if d.ID != "d1" {
		t.Errorf("domain ID = %q, want d1", d.ID)
	}
}

func TestClient_DeleteDomain_NoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	if err := c.DeleteDomain(context.Background(), "d1"); err != nil {
		t.Errorf("DeleteDomain: %v", err)
	}
}

func TestClient_NetworkError_ReturnsErrNetwork(t *testing.T) {
	// Point at a server that is not listening.
	c := api.NewClient("http://127.0.0.1:1", "kk_test", "dev", "linux", "amd64")
	_, err := c.GetProfile(context.Background())
	if _, ok := err.(*api.ErrNetwork); !ok {
		t.Errorf("err type = %T, want *api.ErrNetwork", err)
	}
}

func TestClient_ListCerts_StatusFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]api.TlsCert{})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.ListCerts(context.Background(), "issued")
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if gotQuery != "status=issued" {
		t.Errorf("query = %q, want status=issued", gotQuery)
	}
	// Verify correct path prefix used.

}
