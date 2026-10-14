package cert_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/cert"
	"github.com/krakenkey/cli/internal/output"
)

const (
	currentLeafPem = "-----BEGIN CERTIFICATE-----\ncurrent-leaf\n-----END CERTIFICATE-----\n"
	caaReason      = "CAA record for example.com prevents issuance"
)

// renewalAPI simulates the renew and retry routes of an API that keeps the
// current certificate after a failed renewal (KrakenKey/app#201).
type renewalAPI struct {
	// postPath is the route the command calls, e.g. "/certs/tls/42/renew".
	postPath string
	// postBody is the JSON answer to the POST.
	postBody string
	// serverTime is sent as the Date header of every response. Zero means
	// no Date header at all.
	serverTime time.Time
	// renewingPolls is how many GETs report "renewing" before final.
	renewingPolls int32
	// final is the certificate the GETs report once the renewal ended.
	final api.TlsCert

	posted atomic.Bool
	gets   atomic.Int32
}

func (a *renewalAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.serverTime.IsZero() {
			// Stop net/http from adding its own Date header.
			w.Header()["Date"] = nil
		} else {
			w.Header().Set("Date", a.serverTime.UTC().Format(http.TimeFormat))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == a.postPath:
			a.posted.Store(true)
			_, _ = w.Write([]byte(a.postBody))
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/42/chain":
			_ = json.NewEncoder(w).Encode(api.TlsCertChainInfo{FullChainPem: a.final.CrtPem + a.final.ChainPem})
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/42":
			c := a.final
			if a.gets.Add(1) <= a.renewingPolls {
				c = api.TlsCert{ID: 42, Status: api.CertStatusRenewing, CrtPem: currentLeafPem}
			}
			c.ParsedCsr = &api.ParsedCsr{Subject: []api.CsrSubjectField{{Name: "commonName", Value: "renew.example.com"}}}
			_ = json.NewEncoder(w).Encode(c)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ptrTime(t time.Time) *time.Time { return &t }

// keptCert is the certificate after a failed renewal: still issued, with the
// current PEM, the failure time and the reason.
func keptCert(failedAt time.Time) api.TlsCert {
	return api.TlsCert{
		ID:              42,
		Status:          api.CertStatusIssued,
		CrtPem:          currentLeafPem,
		ChainPem:        renewedChainPem,
		ExpiresAt:       ptrTime(time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)),
		FailureReason:   caaReason,
		RenewalFailedAt: &failedAt,
	}
}

func renewedCert() api.TlsCert {
	return api.TlsCert{ID: 42, Status: api.CertStatusIssued, CrtPem: renewedLeafPem, ChainPem: renewedChainPem}
}

func waitOpts(dir string) cert.RenewOptions {
	return cert.RenewOptions{
		Out:          filepath.Join(dir, "site.crt"),
		ChainOut:     filepath.Join(dir, "site.chain.crt"),
		FullchainOut: filepath.Join(dir, "site.fullchain.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	}
}

func assertNoFiles(t *testing.T, dir string) {
	t.Helper()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("wrote %d file(s), want none", len(entries))
	}
}

func TestRunRenew_WaitFailsWhenRenewalFailedAndCertKept(t *testing.T) {
	now := time.Now()
	a := &renewalAPI{
		postPath:      "/certs/tls/42/renew",
		postBody:      `{"id":42,"status":"renewing","queued":false}`,
		serverTime:    now,
		renewingPolls: 1,
		final:         keptCert(now.Add(2 * time.Second)),
	}
	srv := a.server(t)

	dir := t.TempDir()
	printer, out, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, waitOpts(dir))
	if err == nil {
		t.Fatal("RunRenew succeeded, want an error for a failed renewal")
	}
	want := "renewal failed for certificate 42: " + caaReason + "; the current certificate is still in place (expires 2026-11-20)"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	assertNoFiles(t, dir)
	if strings.Contains(out.String(), "renewed") {
		t.Errorf("output = %q, should not say the certificate was renewed", out.String())
	}
}

// The server's clock is an hour behind the local one. The failure happened
// after the request by the server's clock, so it counts, although it is an
// hour earlier than the local time of the request.
func TestRunRenew_WaitUsesServerTime(t *testing.T) {
	serverNow := time.Now().Add(-time.Hour)
	a := &renewalAPI{
		postPath:   "/certs/tls/42/renew",
		postBody:   `{"id":42,"status":"renewing"}`,
		serverTime: serverNow,
		final:      keptCert(serverNow.Add(5 * time.Second)),
	}
	srv := a.server(t)

	printer, _, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, waitOpts(t.TempDir()))
	if err == nil || !strings.Contains(err.Error(), "renewal failed for certificate 42") {
		t.Fatalf("err = %v, want a failed renewal", err)
	}
}

// Without a Date header the local clock is the reference.
func TestRunRenew_WaitWithoutDateHeaderUsesLocalTime(t *testing.T) {
	a := &renewalAPI{
		postPath: "/certs/tls/42/renew",
		postBody: `{"id":42,"status":"renewing"}`,
		final:    keptCert(time.Now().Add(time.Second)),
	}
	srv := a.server(t)

	printer, _, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, waitOpts(t.TempDir()))
	if err == nil || !strings.Contains(err.Error(), caaReason) {
		t.Fatalf("err = %v, want a failed renewal with the reason", err)
	}
}

// A renewalFailedAt well before the request belongs to an earlier renewal
// (the API clears it when a renewal starts, so this only happens when a
// server that predates the field handled the request). It must not turn a
// renewal into a failure.
func TestRunRenew_WaitIgnoresEarlierRenewalFailure(t *testing.T) {
	now := time.Now()
	final := renewedCert()
	final.RenewalFailedAt = ptrTime(now.Add(-time.Hour))
	a := &renewalAPI{
		postPath:   "/certs/tls/42/renew",
		postBody:   `{"id":42,"status":"renewing"}`,
		serverTime: now,
		final:      final,
	}
	srv := a.server(t)

	dir := t.TempDir()
	printer, out, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, waitOpts(dir)); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	if got := mustReadFile(t, filepath.Join(dir, "site.crt")); got != renewedLeafPem {
		t.Errorf("cert = %q, want the renewed leaf", got)
	}
	if !strings.Contains(out.String(), "Certificate 42 renewed") {
		t.Errorf("output = %q, want 'Certificate 42 renewed'", out.String())
	}
}

// A small clock difference between the proxy that sets Date and the API
// that records renewalFailedAt must not hide a failure.
func TestRunRenew_WaitToleratesClockSkew(t *testing.T) {
	now := time.Now()
	a := &renewalAPI{
		postPath:   "/certs/tls/42/renew",
		postBody:   `{"id":42,"status":"renewing"}`,
		serverTime: now,
		final:      keptCert(now.Add(-30 * time.Second)),
	}
	srv := a.server(t)

	printer, _, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, waitOpts(t.TempDir())); err == nil {
		t.Fatal("RunRenew succeeded, want a failed renewal")
	}
}

func TestRunRetry_WaitFailsWhenRenewalFailsAgain(t *testing.T) {
	now := time.Now()
	a := &renewalAPI{
		postPath:      "/certs/tls/42/retry",
		postBody:      `{"id":42,"status":"renewing","queued":false}`,
		serverTime:    now,
		renewingPolls: 1,
		final:         keptCert(now.Add(time.Second)),
	}
	srv := a.server(t)

	dir := t.TempDir()
	printer, out, _ := newPrinter()
	err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Out:          filepath.Join(dir, "site.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "renewal failed again for certificate 42 after retry: "+caaReason) {
		t.Fatalf("err = %v, want a failed renewal after retry", err)
	}
	assertNoFiles(t, dir)
	if strings.Contains(out.String(), "Certificate 42 issued") {
		t.Errorf("output = %q, should not say the certificate was issued", out.String())
	}
}

func TestRunRetry_WaitSavesRenewedCertAfterFailedRenewal(t *testing.T) {
	a := &renewalAPI{
		postPath:      "/certs/tls/42/retry",
		postBody:      `{"id":42,"status":"renewing","queued":true}`,
		serverTime:    time.Now(),
		renewingPolls: 1,
		final:         renewedCert(),
	}
	srv := a.server(t)

	dir := t.TempDir()
	printer, out, _ := newPrinter()
	err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Out:          filepath.Join(dir, "site.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunRetry: %v", err)
	}
	if got := mustReadFile(t, filepath.Join(dir, "site.crt")); got != renewedLeafPem {
		t.Errorf("cert = %q, want the renewed leaf", got)
	}
	if !strings.Contains(out.String(), "Certificate 42 issued") {
		t.Errorf("output = %q", out.String())
	}
}

func TestRunRetry_JSONPassesQueued(t *testing.T) {
	a := &renewalAPI{
		postPath: "/certs/tls/42/retry",
		postBody: `{"id":42,"status":"renewing","queued":true}`,
	}
	srv := a.server(t)

	out := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, &bytes.Buffer{})
	if err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{}); err != nil {
		t.Fatalf("RunRetry: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, out.String())
	}
	if got["queued"] != true || got["status"] != "renewing" {
		t.Errorf("JSON = %s, want status renewing and queued true", out.String())
	}
}

const (
	inProgressBody       = `{"id":42,"status":"renewing","skipped":true,"reason":"in_progress","queued":false}`
	inProgressQueuedBody = `{"id":42,"status":"renewing","skipped":true,"reason":"in_progress","queued":true}`
)

func TestRunRenew_IfDue_InProgressWithoutWait(t *testing.T) {
	a := &renewalAPI{postPath: "/certs/tls/42/renew", postBody: inProgressBody, final: renewedCert()}
	srv := a.server(t)

	printer, out, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{IfDue: true}); err != nil {
		t.Fatalf("RunRenew: %v (an in-progress skip must exit 0)", err)
	}
	want := "A renewal of certificate 42 is already running; not starting another"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
	for _, bad := range []string{"not due", "Renewal triggered"} {
		if strings.Contains(out.String(), bad) {
			t.Errorf("output = %q, should not contain %q", out.String(), bad)
		}
	}
	if n := a.gets.Load(); n != 0 {
		t.Errorf("polled %d time(s) without --wait, want 0", n)
	}
}

func TestRunRenew_IfDue_InProgressQueuedMessage(t *testing.T) {
	a := &renewalAPI{postPath: "/certs/tls/42/renew", postBody: inProgressQueuedBody}
	srv := a.server(t)

	printer, out, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{IfDue: true}); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	want := "A renewal of certificate 42 is already waiting for a free slot; not starting another"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

func TestRunRenew_IfDue_InProgressJSON(t *testing.T) {
	a := &renewalAPI{postPath: "/certs/tls/42/renew", postBody: inProgressQueuedBody}
	srv := a.server(t)

	out := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, &bytes.Buffer{})
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{IfDue: true}); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, out.String())
	}
	want := map[string]any{"id": float64(42), "skipped": true, "reason": "in_progress", "queued": true}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("JSON %s = %v, want %v (full: %s)", k, got[k], v, out.String())
		}
	}
}

func TestRunRenew_IfDue_InProgressWaitSavesRenewedCert(t *testing.T) {
	a := &renewalAPI{
		postPath:      "/certs/tls/42/renew",
		postBody:      inProgressQueuedBody,
		serverTime:    time.Now(),
		renewingPolls: 2,
		final:         renewedCert(),
	}
	srv := a.server(t)

	dir := t.TempDir()
	opts := waitOpts(dir)
	opts.IfDue = true
	printer, out, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, opts); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	if a.gets.Load() < 3 {
		t.Errorf("polled %d time(s), want to wait until the renewal finished", a.gets.Load())
	}
	if got := mustReadFile(t, filepath.Join(dir, "site.crt")); got != renewedLeafPem {
		t.Errorf("cert = %q, want the renewed leaf", got)
	}
	for _, want := range []string{
		"A renewal of certificate 42 is already waiting for a free slot; waiting for it to finish",
		"Certificate 42 renewed",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output = %q, want %q", out.String(), want)
		}
	}
	if strings.Contains(out.String(), "Renewal triggered") {
		t.Errorf("output = %q, should not say this command triggered a renewal", out.String())
	}
}

func TestRunRenew_IfDue_InProgressWaitJSONPrintsCert(t *testing.T) {
	a := &renewalAPI{
		postPath:   "/certs/tls/42/renew",
		postBody:   inProgressBody,
		serverTime: time.Now(),
		final:      renewedCert(),
	}
	srv := a.server(t)

	opts := waitOpts(t.TempDir())
	opts.IfDue = true
	out := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, &bytes.Buffer{})
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, opts); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, out.String())
	}
	if got["crtPem"] != renewedLeafPem || got["skipped"] != nil {
		t.Errorf("JSON = %s, want the renewed certificate", out.String())
	}
}

func TestRunRenew_IfDue_InProgressWaitReportsFailure(t *testing.T) {
	now := time.Now()
	a := &renewalAPI{
		postPath:      "/certs/tls/42/renew",
		postBody:      inProgressBody,
		serverTime:    now,
		renewingPolls: 1,
		final:         keptCert(now.Add(time.Second)),
	}
	srv := a.server(t)

	dir := t.TempDir()
	opts := waitOpts(dir)
	opts.IfDue = true
	printer, _, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, opts)
	if err == nil || !strings.Contains(err.Error(), "renewal failed for certificate 42: "+caaReason) {
		t.Fatalf("err = %v, want the in-progress renewal's failure", err)
	}
	assertNoFiles(t, dir)
}

func TestRunRenew_IfDue_InProgressWaitHonorsPollTimeout(t *testing.T) {
	a := &renewalAPI{
		postPath:      "/certs/tls/42/renew",
		postBody:      inProgressBody,
		renewingPolls: 1 << 30,
	}
	srv := a.server(t)

	opts := waitOpts(t.TempDir())
	opts.IfDue = true
	opts.PollTimeout = 100 * time.Millisecond
	printer, _, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, opts)
	if err == nil || !strings.Contains(err.Error(), "timed out after 100ms waiting for certificate 42") {
		t.Fatalf("err = %v, want a poll timeout", err)
	}
}

func TestRunRenew_IfDue_NotDueAfterFailedRenewal(t *testing.T) {
	body := `{"id":42,"status":"issued","skipped":true,"reason":"not_due","expiresAt":"2026-11-20T10:00:00.000Z","renewalWindowDays":30,"retryAfter":"2026-10-15T02:03:12.000Z"}`
	a := &renewalAPI{postPath: "/certs/tls/42/renew", postBody: body}
	srv := a.server(t)

	printer, out, _ := newPrinter()
	opts := waitOpts(t.TempDir())
	opts.IfDue = true
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, opts); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	want := "Certificate 42 is not due for renewal (expires 2026-11-20, renewal window 30 days); the last renewal failed, and --if-due tries again after 2026-10-15 02:03 UTC (renew without --if-due to try now)"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
	if n := a.gets.Load(); n != 0 {
		t.Errorf("polled %d time(s) after a not_due skip, want 0", n)
	}
}

func TestRunShow_RenewalFailed(t *testing.T) {
	c := keptCert(time.Date(2026, 10, 14, 6, 3, 12, 0, time.UTC))
	c.CreatedAt = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/certs/tls/42" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(c)
	}))
	defer srv.Close()

	printer, out, _ := newPrinter()
	if err := cert.RunShow(context.Background(), newTestClient(srv.URL), printer, 42); err != nil {
		t.Fatalf("RunShow: %v", err)
	}
	for _, want := range []string{
		"Renewal:     failed 2026-10-14T06:03:12Z, current certificate kept",
		"Reason:      " + caaReason,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}
