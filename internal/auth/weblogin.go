package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"time"

	"github.com/krakenkey/cli/internal/api"
)

// WebLoginOptions configures RunWebLogin.
type WebLoginOptions struct {
	// ClientName is shown on the approval page and used in the key name.
	// Defaults to the hostname.
	ClientName string
	// OpenBrowser tries to open the approval link in the default browser.
	OpenBrowser bool
	// Out receives the instructions for the user (default os.Stderr, so
	// stdout stays clean for --output json).
	Out io.Writer
	// Open overrides how the browser is launched (tests).
	Open func(url string) error
	// Sleep overrides waiting between polls (tests).
	Sleep func(ctx context.Context, d time.Duration) error
}

var clientNameUnsafe = regexp.MustCompile(`[^\w .@()-]`)

// DefaultClientName returns the hostname, trimmed to what the API accepts.
func DefaultClientName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "krakenkey CLI"
	}
	host = clientNameUnsafe.ReplaceAllString(host, "")
	if len(host) > 64 {
		host = host[:64]
	}
	if host == "" {
		return "krakenkey CLI"
	}
	return host
}

// RunWebLogin starts a browser login, waits for the user to approve it in
// the dashboard, and returns the new API key. client must not carry an API
// key. Saving the key is left to the caller (see RunLogin).
func RunWebLogin(ctx context.Context, client *api.Client, opts WebLoginOptions) (*api.DeviceToken, error) {
	if opts.Out == nil {
		opts.Out = os.Stderr
	}
	if opts.Open == nil {
		opts.Open = openBrowser
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepCtx
	}
	if opts.ClientName == "" {
		opts.ClientName = DefaultClientName()
	}

	dc, err := client.StartDeviceLogin(ctx, opts.ClientName)
	if err != nil {
		return nil, err
	}

	_, _ = fmt.Fprintf(opts.Out, "To sign in, open this link and approve the request:\n\n  %s\n\n", dc.VerificationURIComplete)
	_, _ = fmt.Fprintf(opts.Out, "Check that the page shows code %s. Waiting for approval (expires in %d minutes)...\n", dc.UserCode, (dc.ExpiresIn+59)/60)
	if opts.OpenBrowser {
		_ = opts.Open(dc.VerificationURIComplete)
	}

	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)

	for {
		if err := opts.Sleep(ctx, interval); err != nil {
			return nil, err
		}
		tok, err := client.PollDeviceLogin(ctx, dc.DeviceCode)
		if err != nil {
			return nil, err
		}
		switch tok.Status {
		case api.DeviceStatusApproved:
			if tok.APIKey == "" {
				return nil, fmt.Errorf("login approved but no API key was returned")
			}
			return tok, nil
		case api.DeviceStatusDenied:
			return nil, &api.ErrAuth{Message: "login request was denied"}
		case api.DeviceStatusExpired:
			return nil, &api.ErrAuth{Message: "login request expired; run `krakenkey auth login --web` again"}
		case api.DeviceStatusSlowDown:
			// RFC 8628 §3.5: back off by 5 seconds.
			interval += 5 * time.Second
		}
		if time.Now().After(deadline) {
			return nil, &api.ErrAuth{Message: "login request expired; run `krakenkey auth login --web` again"}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
