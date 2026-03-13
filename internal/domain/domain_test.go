package domain_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/domain"
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

func TestRunAdd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["hostname"] != "example.com" {
			t.Errorf("hostname = %q, want example.com", body["hostname"])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.Domain{
			ID:               "d1",
			Hostname:         "example.com",
			VerificationCode: "krakenkey-site-verification=abc123",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := domain.RunAdd(context.Background(), client, printer, "example.com")
	if err != nil {
		t.Fatalf("RunAdd: %v", err)
	}

	got := out.String()
	for _, want := range []string{"example.com", "krakenkey-site-verification=abc123", "TXT"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunAdd_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(api.APIError{StatusCode: 400, Message: "invalid hostname"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := domain.RunAdd(context.Background(), client, printer, "bad..host")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRunList_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]api.Domain{})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := domain.RunList(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunList: %v", err)
	}
	if !strings.Contains(out.String(), "No domains") {
		t.Errorf("output = %q, want 'No domains' message", out.String())
	}
}

func TestRunList_WithDomains(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	domains := []api.Domain{
		{ID: "d1", Hostname: "example.com", IsVerified: true, CreatedAt: now},
		{ID: "d2", Hostname: "test.io", IsVerified: false, CreatedAt: now},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(domains)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := domain.RunList(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunList: %v", err)
	}

	got := out.String()
	for _, want := range []string{"example.com", "test.io", "yes", "no"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunShow_Success(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	d := api.Domain{
		ID:               "d1",
		Hostname:         "example.com",
		IsVerified:       true,
		VerificationCode: "krakenkey-site-verification=xyz789",
		CreatedAt:        now,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domains/d1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := domain.RunShow(context.Background(), client, printer, "d1")
	if err != nil {
		t.Fatalf("RunShow: %v", err)
	}

	got := out.String()
	for _, want := range []string{"d1", "example.com", "true", "krakenkey-site-verification=xyz789"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunVerify_Verified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domains/d1/verify" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.Domain{
			ID:         "d1",
			Hostname:   "example.com",
			IsVerified: true,
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := domain.RunVerify(context.Background(), client, printer, "d1")
	if err != nil {
		t.Fatalf("RunVerify: %v", err)
	}
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("output = %q, want 'verified'", out.String())
	}
}

func TestRunVerify_NotVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.Domain{
			ID:         "d1",
			Hostname:   "example.com",
			IsVerified: false,
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := domain.RunVerify(context.Background(), client, printer, "d1")
	if err == nil {
		t.Fatal("expected error for unverified domain, got nil")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("error = %q, want to contain 'verification failed'", err.Error())
	}
}

func TestRunDelete_Success(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := domain.RunDelete(context.Background(), client, printer, "d1")
	if err != nil {
		t.Fatalf("RunDelete: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/domains/d1" {
		t.Errorf("path = %q, want /domains/d1", gotPath)
	}
	if !strings.Contains(out.String(), "deleted") {
		t.Errorf("output = %q, want 'deleted'", out.String())
	}
}

func TestRunDelete_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(api.APIError{StatusCode: 404, Message: "Not found"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := domain.RunDelete(context.Background(), client, printer, "nonexistent")
	if _, ok := err.(*api.ErrNotFound); !ok {
		t.Errorf("err type = %T, want *api.ErrNotFound", err)
	}
}
