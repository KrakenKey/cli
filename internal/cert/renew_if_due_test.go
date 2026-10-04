package cert_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/cert"
	"github.com/krakenkey/cli/internal/output"
)

const notDueBody = `{"id":42,"status":"issued","skipped":true,"reason":"not_due","expiresAt":"2026-12-01T08:00:00.000Z","renewalWindowDays":30}`

// ifDueServer answers POST /certs/tls/42/renew with renewStatus and
// renewBody, records the query string, and counts GET /certs/tls/42 polls
// (reporting the cert as issued).
func ifDueServer(t *testing.T, renewStatus int, renewBody string, gotQuery *string, polls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/certs/tls/42/renew":
			*gotQuery = r.URL.RawQuery
			w.WriteHeader(renewStatus)
			_, _ = w.Write([]byte(renewBody))
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/42":
			polls.Add(1)
			json.NewEncoder(w).Encode(api.TlsCert{ID: 42, Status: "issued"})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestRunRenew_IfDue_NotDueSkips(t *testing.T) {
	var gotQuery string
	var polls atomic.Int32
	srv := ifDueServer(t, http.StatusOK, notDueBody, &gotQuery, &polls)
	defer srv.Close()

	printer, out, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
		IfDue:        true,
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("RunRenew: %v (a skipped renewal must exit 0)", err)
	}
	if gotQuery != "ifDue=true" {
		t.Errorf("query = %q, want ifDue=true", gotQuery)
	}
	if n := polls.Load(); n != 0 {
		t.Errorf("polled %d time(s) after a skipped renewal, want 0", n)
	}
	want := "Certificate 42 is not due for renewal (expires 2026-12-01, renewal window 30 days)"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
	if strings.Contains(out.String(), "Renewal triggered") {
		t.Errorf("output = %q, should not say a renewal was triggered", out.String())
	}
}

func TestRunRenew_IfDue_NotDueJSON(t *testing.T) {
	var gotQuery string
	var polls atomic.Int32
	srv := ifDueServer(t, http.StatusOK, notDueBody, &gotQuery, &polls)
	defer srv.Close()

	out := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, &bytes.Buffer{})
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{IfDue: true}); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not a single JSON object: %v\n%s", err, out.String())
	}
	want := map[string]any{
		"id":                float64(42),
		"status":            "issued",
		"skipped":           true,
		"reason":            "not_due",
		"expiresAt":         "2026-12-01T08:00:00Z",
		"renewalWindowDays": float64(30),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("JSON %s = %v, want %v (full: %s)", k, got[k], v, out.String())
		}
	}
}

func TestRunRenew_IfDue_DueRenewsAndWaits(t *testing.T) {
	var gotQuery string
	var polls atomic.Int32
	srv := ifDueServer(t, http.StatusCreated, `{"id":42,"status":"renewing","skipped":false}`, &gotQuery, &polls)
	defer srv.Close()

	printer, out, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
		IfDue:        true,
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	if gotQuery != "ifDue=true" {
		t.Errorf("query = %q, want ifDue=true", gotQuery)
	}
	if polls.Load() == 0 {
		t.Error("did not poll after a renewal was started")
	}
	for _, want := range []string{"Renewal triggered for certificate 42", "Certificate 42 renewed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output = %q, want %q", out.String(), want)
		}
	}
	if strings.Contains(out.String(), "did not say") {
		t.Errorf("output = %q, should not warn when the API sent skipped=false", out.String())
	}
}

// An API without ifDue support ignores the parameter, renews, and omits the
// skipped field. The CLI cannot undo that, but it should say so.
func TestRunRenew_IfDue_OldAPIRenewsWithNotice(t *testing.T) {
	var gotQuery string
	var polls atomic.Int32
	srv := ifDueServer(t, http.StatusCreated, `{"id":42,"status":"renewing"}`, &gotQuery, &polls)
	defer srv.Close()

	printer, out, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{IfDue: true}); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	if !strings.Contains(out.String(), "may not support --if-due") {
		t.Errorf("output = %q, want a notice that the API ignored --if-due", out.String())
	}
	if !strings.Contains(out.String(), "Renewal triggered") {
		t.Errorf("output = %q, want 'Renewal triggered'", out.String())
	}
}

func TestRunRenew_WithoutIfDue_SendsNoQuery(t *testing.T) {
	var gotQuery string
	var polls atomic.Int32
	srv := ifDueServer(t, http.StatusCreated, `{"id":42,"status":"renewing"}`, &gotQuery, &polls)
	defer srv.Close()

	printer, out, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{}); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want none without --if-due", gotQuery)
	}
	if strings.Contains(out.String(), "may not support --if-due") {
		t.Errorf("output = %q, should not mention --if-due when it was not used", out.String())
	}
}
