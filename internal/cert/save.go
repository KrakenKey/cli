package cert

import (
	"context"
	"fmt"
	"os"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// certOutputs holds the output paths for an issued certificate. Empty paths
// fall back to ./<base>.crt, ./<base>.chain.crt and ./<base>.fullchain.crt.
type certOutputs struct {
	Out          string
	ChainOut     string
	FullchainOut string
}

// saveIssuedCert writes the leaf certificate, the intermediate chain and the
// full chain of an issued certificate to disk; see saveChainFiles for how a
// missing chain is handled. It is shared by `cert issue`, `cert submit`,
// `cert renew` and `cert retry` so all of them write the same files once the
// certificate is ready. base names the default files when a path is empty.
func saveIssuedCert(ctx context.Context, client *api.Client, printer *output.Printer, c *api.TlsCert, base string, paths certOutputs) error {
	if c.CrtPem == "" {
		return nil
	}

	certOut := paths.Out
	if certOut == "" {
		certOut = base + ".crt"
	}
	chainOut := paths.ChainOut
	if chainOut == "" {
		chainOut = base + ".chain.crt"
	}
	fullchainOut := paths.FullchainOut
	if fullchainOut == "" {
		fullchainOut = base + ".fullchain.crt"
	}

	if err := os.WriteFile(certOut, []byte(c.CrtPem), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	printer.Info("Certificate saved to %s", certOut)

	return saveChainFiles(ctx, client, printer, c, chainOutputs{
		CertOut:            certOut,
		ChainOut:           chainOut,
		FullchainOut:       fullchainOut,
		ChainRequested:     paths.ChainOut != "",
		FullchainRequested: paths.FullchainOut != "",
	})
}

// applyAutoRenew sets the auto-renew preference on a newly submitted
// certificate. A nil value leaves the API default (on) untouched and makes no
// request. A failure is reported on stderr but is not fatal: the certificate
// request itself already succeeded, and the setting can be changed afterwards
// with `krakenkey cert update`.
func applyAutoRenew(ctx context.Context, client *api.Client, printer *output.Printer, id int, autoRenew *bool) {
	if autoRenew == nil {
		return
	}
	if _, err := client.UpdateCert(ctx, id, autoRenew); err != nil {
		verb, state := "enable", "true"
		if !*autoRenew {
			verb, state = "disable", "false"
		}
		printer.Error("Failed to %s auto-renew for certificate %d: %s (the certificate keeps the API default; run `krakenkey cert update %d --auto-renew=%s` to retry)", verb, id, err, id, state)
	}
}
