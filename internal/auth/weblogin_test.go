package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/auth"
)

// deviceServer serves /auth/device/code and answers token polls from statuses
// in order, repeating the last one.
type deviceServer struct {
	t        *testing.T
	statuses []api.DeviceToken
	mu       sync.Mutex
	polls    int
	authSeen []string
	name     string
}

func (d *deviceServer) handler(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.authSeen = append(d.authSeen, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)

	switch r.URL.Path {
	case "/auth/device/code":
		d.name = body["clientName"]
		_ = json.NewEncoder(w).Encode(api.DeviceCode{
			DeviceCode:              "dc_123",
			UserCode:                "BCDF-GHJK",
			VerificationURI:         "https://app.example.com/device",
			VerificationURIComplete: "https://app.example.com/device?code=BCDF-GHJK",
			ExpiresIn:               600,
			Interval:                5,
		})
	case "/auth/device/token":
		if body["deviceCode"] != "dc_123" {
			d.t.Errorf("deviceCode = %q", body["deviceCode"])
		}
		i := d.polls
		if i >= len(d.statuses) {
			i = len(d.statuses) - 1
		}
		d.polls++
		_ = json.NewEncoder(w).Encode(d.statuses[i])
	default:
		http.NotFound(w, r)
	}
}

type webResult struct {
	tok    *api.DeviceToken
	err    error
	server *deviceServer
	out    *bytes.Buffer
	waits  []time.Duration
	opened []string
}

func runWeb(t *testing.T, statuses ...api.DeviceToken) webResult {
	t.Helper()
	ds := &deviceServer{t: t, statuses: statuses}
	srv := httptest.NewServer(http.HandlerFunc(ds.handler))
	t.Cleanup(srv.Close)

	var waits []time.Duration
	var opened []string
	out := &bytes.Buffer{}
	client := api.NewClient(srv.URL, "", "v0.0.0", "linux", "amd64")
	tok, err := auth.RunWebLogin(context.Background(), client, auth.WebLoginOptions{
		ClientName:  "build-01",
		OpenBrowser: true,
		Out:         out,
		Open:        func(u string) error { opened = append(opened, u); return nil },
		Sleep: func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		},
	})
	return webResult{tok, err, ds, out, waits, opened}
}

func TestRunWebLogin_Approved(t *testing.T) {
	r := runWeb(t,
		api.DeviceToken{Status: api.DeviceStatusPending},
		api.DeviceToken{Status: api.DeviceStatusSlowDown},
		api.DeviceToken{Status: api.DeviceStatusApproved, APIKey: "kk_new", ID: "key-1", Name: "CLI login: build-01"},
	)
	tok, err, ds, out, waits, opened := r.tok, r.err, r.server, r.out, r.waits, r.opened
	if err != nil {
		t.Fatalf("RunWebLogin: %v", err)
	}
	if tok.APIKey != "kk_new" || tok.ID != "key-1" {
		t.Errorf("token = %+v", tok)
	}
	if ds.name != "build-01" {
		t.Errorf("clientName = %q", ds.name)
	}
	for _, a := range ds.authSeen {
		if a != "" {
			t.Errorf("sent Authorization %q on an unauthenticated call", a)
		}
	}
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("wait %d = %v, want %v (slow_down adds 5s)", i, waits[i], want[i])
		}
	}
	got := out.String()
	for _, s := range []string{"https://app.example.com/device?code=BCDF-GHJK", "BCDF-GHJK", "10 minutes"} {
		if !strings.Contains(got, s) {
			t.Errorf("instructions missing %q:\n%s", s, got)
		}
	}
	if len(opened) != 1 || opened[0] != "https://app.example.com/device?code=BCDF-GHJK" {
		t.Errorf("opened = %v", opened)
	}
}

func TestRunWebLogin_DeniedAndExpired(t *testing.T) {
	for _, status := range []string{api.DeviceStatusDenied, api.DeviceStatusExpired} {
		t.Run(status, func(t *testing.T) {
			err := runWeb(t, api.DeviceToken{Status: status}).err
			var authErr *api.ErrAuth
			if !errors.As(err, &authErr) || !strings.Contains(authErr.Message, status) {
				t.Errorf("err = %v, want ErrAuth mentioning %q", err, status)
			}
		})
	}
}

func TestRunWebLogin_ApprovedWithoutKeyIsAnError(t *testing.T) {
	err := runWeb(t, api.DeviceToken{Status: api.DeviceStatusApproved}).err
	if err == nil {
		t.Fatal("expected an error when no key comes back")
	}
}

func TestDefaultClientName(t *testing.T) {
	name := auth.DefaultClientName()
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "<>\"'/") {
		t.Errorf("DefaultClientName() = %q", name)
	}
}
