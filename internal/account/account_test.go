package account_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/account"
	"github.com/krakenkey/cli/internal/api"
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

func TestRunShow_Success(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	profile := api.UserProfile{
		ID:          "u1",
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		Plan:        "pro",
		CreatedAt:   now,
		ResourceCounts: api.ResourceCounts{
			Domains:      3,
			Certificates: 7,
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

	err := account.RunShow(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunShow: %v", err)
	}

	got := out.String()
	for _, want := range []string{"u1", "alice", "alice@example.com", "Alice", "pro", "3", "7", "2", "2026"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunShow_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(api.APIError{StatusCode: 401, Message: "Unauthorized"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := account.RunShow(context.Background(), client, printer)
	if _, ok := err.(*api.ErrAuth); !ok {
		t.Errorf("err type = %T, want *api.ErrAuth", err)
	}
}

func TestRunPlan_ProPlan(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	sub := api.Subscription{
		Plan:              "pro",
		Status:            "active",
		CurrentPeriodEnd:  &end,
		CancelAtPeriodEnd: false,
		CreatedAt:         now,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sub)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := account.RunPlan(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	got := out.String()
	for _, want := range []string{"pro", "active", "2026-02-01", "Subscribed"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunPlan_FreeTier_ZeroCreatedAt(t *testing.T) {
	sub := api.Subscription{
		Plan:   "free",
		Status: "active",
		// No CurrentPeriodEnd, no CreatedAt (zero value) for free tier.
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sub)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := account.RunPlan(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "free") {
		t.Errorf("output missing 'free':\n%s", got)
	}
	// Should NOT print "Subscribed:" line when createdAt is zero.
	if strings.Contains(got, "Subscribed") {
		t.Errorf("output should not contain 'Subscribed' for free tier:\n%s", got)
	}
	// Should NOT print "Current period ends:" when nil.
	if strings.Contains(got, "period ends") {
		t.Errorf("output should not contain period end for free tier:\n%s", got)
	}
}

func TestRunPlan_CancelAtPeriodEnd(t *testing.T) {
	end := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	sub := api.Subscription{
		Plan:              "pro",
		Status:            "active",
		CurrentPeriodEnd:  &end,
		CancelAtPeriodEnd: true,
		CreatedAt:         now,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sub)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := account.RunPlan(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	if !strings.Contains(out.String(), "cancel") {
		t.Errorf("output should mention cancellation:\n%s", out.String())
	}
}
