package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/auth"
	"github.com/krakenkey/cli/internal/config"
	"github.com/krakenkey/cli/internal/output"
)

func newTestClient(baseURL string) *api.Client {
	return api.NewClient(baseURL, "kk_test", "v0.0.0", "linux", "amd64")
}

func newPrinter() (*output.Printer, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	return output.NewWithWriters("text", true, out, errOut), out, errOut
}

func TestRunLogin_Success(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/profile" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.UserProfile{
			ID:          "u1",
			DisplayName: "Alice",
			Email:       "alice@example.com",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := auth.RunLogin(context.Background(), client, printer, "kk_test_key")
	if err != nil {
		t.Fatalf("RunLogin: %v", err)
	}
	if got := out.String(); !contains(got, "Alice") || !contains(got, "alice@example.com") {
		t.Errorf("output = %q, want to contain user info", got)
	}

	// Verify key was saved to config.
	t.Setenv("KK_API_KEY", "")
	t.Setenv("KK_API_URL", "")
	t.Setenv("KK_OUTPUT", "")
	cfg, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.APIKey != "kk_test_key" {
		t.Errorf("saved API key = %q, want kk_test_key", cfg.APIKey)
	}
}

func TestRunLogin_AuthError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(api.APIError{StatusCode: 401, Message: "Unauthorized"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := auth.RunLogin(context.Background(), client, printer, "kk_bad_key")
	if _, ok := err.(*api.ErrAuth); !ok {
		t.Errorf("err type = %T, want *api.ErrAuth", err)
	}
}

func TestRunLogout_Success(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// Save a key first so there's something to remove.
	if err := config.Save("", "kk_to_remove", ""); err != nil {
		t.Fatalf("config.Save: %v", err)
	}

	printer, out, _ := newPrinter()
	err := auth.RunLogout(printer)
	if err != nil {
		t.Fatalf("RunLogout: %v", err)
	}
	if !contains(out.String(), "Logged out") {
		t.Errorf("output = %q, want to contain 'Logged out'", out.String())
	}

	// Verify key was removed.
	t.Setenv("KK_API_KEY", "")
	t.Setenv("KK_API_URL", "")
	t.Setenv("KK_OUTPUT", "")
	cfg, _ := config.Load(config.Flags{})
	if cfg.APIKey != "" {
		t.Errorf("API key still present after logout: %q", cfg.APIKey)
	}
}

func TestRunStatus_Success(t *testing.T) {
	profile := api.UserProfile{
		ID:          "u1",
		DisplayName: "Bob",
		Email:       "bob@example.com",
		Plan:        "pro",
		ResourceCounts: api.ResourceCounts{
			Domains:      3,
			Certificates: 5,
			APIKeys:      2,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(profile)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := auth.RunStatus(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	got := out.String()
	for _, want := range []string{"Bob", "bob@example.com", "pro", "3", "5", "2"} {
		if !contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunKeysList_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]api.APIKey{})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := auth.RunKeysList(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunKeysList: %v", err)
	}
	if !contains(out.String(), "No API keys") {
		t.Errorf("output = %q, want 'No API keys' message", out.String())
	}
}

func TestRunKeysList_WithKeys(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exp := now.Add(30 * 24 * time.Hour)
	keys := []api.APIKey{
		{ID: "k1", Name: "dev-key", CreatedAt: now, ExpiresAt: &exp},
		{ID: "k2", Name: "ci-key", CreatedAt: now, ExpiresAt: nil},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := auth.RunKeysList(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunKeysList: %v", err)
	}

	got := out.String()
	for _, want := range []string{"dev-key", "ci-key", "k1", "k2", "never"} {
		if !contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunKeysCreate_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "my-key" {
			t.Errorf("request body name = %v, want my-key", body["name"])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.CreateAPIKeyResponse{
			ID:     "k1",
			Name:   "my-key",
			APIKey: "kk_secret123",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := auth.RunKeysCreate(context.Background(), client, printer, "my-key", nil)
	if err != nil {
		t.Fatalf("RunKeysCreate: %v", err)
	}

	got := out.String()
	if !contains(got, "kk_secret123") {
		t.Errorf("output missing API key secret:\n%s", got)
	}
	if !contains(got, "k1") {
		t.Errorf("output missing key ID:\n%s", got)
	}
}

func TestRunKeysDelete_Success(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := auth.RunKeysDelete(context.Background(), client, printer, "k1")
	if err != nil {
		t.Fatalf("RunKeysDelete: %v", err)
	}
	if gotPath != "/auth/api-keys/k1" {
		t.Errorf("path = %q, want /auth/api-keys/k1", gotPath)
	}
	if !contains(out.String(), "deleted") {
		t.Errorf("output = %q, want 'deleted'", out.String())
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && bytes.Contains([]byte(s), []byte(substr))
}
