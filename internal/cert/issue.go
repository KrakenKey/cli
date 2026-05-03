package cert

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/csr"
	"github.com/krakenkey/cli/internal/output"
)

// IssueOptions holds parameters for the `cert issue` command.
type IssueOptions struct {
	Domain       string
	SANs         []string
	KeyType      string // "ecdsa-p256" by default
	Org          string
	OU           string
	Locality     string
	State        string
	Country      string
	KeyOut       string // path for private key PEM, default: ./<domain>.key
	CSROut       string // path for CSR PEM, default: ./<domain>.csr
	Out          string // path for certificate PEM, default: ./<domain>.crt
	ChainOut     string // path for chain PEM, default: ./<domain>.chain.crt
	FullchainOut string // path for fullchain PEM, default: ./<domain>.fullchain.crt
	AutoRenew    bool
	Wait         bool
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// RunIssue generates a CSR + private key locally, submits the CSR, and optionally
// polls until the certificate is issued.
func RunIssue(ctx context.Context, client *api.Client, printer *output.Printer, opts IssueOptions) error {
	keyType := opts.KeyType
	if keyType == "" {
		keyType = csr.KeyTypeECDSAP256
	}

	keyOut := opts.KeyOut
	if keyOut == "" {
		keyOut = opts.Domain + ".key"
	}
	csrOut := opts.CSROut
	if csrOut == "" {
		csrOut = opts.Domain + ".csr"
	}
	certOut := opts.Out
	if certOut == "" {
		certOut = opts.Domain + ".crt"
	}
	chainOut := opts.ChainOut
	if chainOut == "" {
		chainOut = opts.Domain + ".chain.crt"
	}
	fullchainOut := opts.FullchainOut
	if fullchainOut == "" {
		fullchainOut = opts.Domain + ".fullchain.crt"
	}

	printer.Info("Generating %s key pair...", keyType)

	result, err := csr.Generate(keyType, csr.Subject{
		CommonName:         opts.Domain,
		Organization:       opts.Org,
		OrganizationalUnit: opts.OU,
		Locality:           opts.Locality,
		State:              opts.State,
		Country:            opts.Country,
	}, opts.SANs)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	// Write private key with restricted permissions — never sent to the API.
	if err := os.WriteFile(keyOut, result.PrivateKeyPem, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	printer.Info("Private key saved to %s", keyOut)

	// Write CSR for reference.
	if err := os.WriteFile(csrOut, result.CSRPem, 0o644); err != nil {
		return fmt.Errorf("write CSR: %w", err)
	}
	printer.Info("CSR saved to %s", csrOut)

	// Submit CSR.
	resp, err := client.CreateCert(ctx, string(result.CSRPem))
	if err != nil {
		return fmt.Errorf("submit CSR: %w", err)
	}
	printer.Info("Certificate request submitted (ID: %d, status: %s)", resp.ID, resp.Status)

	// Set auto-renew if requested.
	if opts.AutoRenew {
		t := true
		if _, err := client.UpdateCert(ctx, resp.ID, &t); err != nil {
			printer.Error("Failed to enable auto-renew: %s", err)
		}
	}

	if !opts.Wait {
		printer.JSON(resp)
		printer.Success("Certificate %d submitted — run `krakenkey cert show %d` to check status", resp.ID, resp.ID)
		return nil
	}

	cert, err := PollUntilDone(ctx, client, printer, resp.ID, opts.PollInterval, opts.PollTimeout)
	if err != nil {
		return err
	}

	if cert.Status == api.CertStatusFailed {
		return fmt.Errorf("certificate issuance failed for %s", opts.Domain)
	}

	if cert.CrtPem != "" {
		if err := os.WriteFile(certOut, []byte(cert.CrtPem), 0o644); err != nil {
			return fmt.Errorf("write certificate: %w", err)
		}
		printer.Info("Certificate saved to %s", certOut)

		if cert.ChainPem != "" {
			if err := os.WriteFile(chainOut, []byte(cert.ChainPem), 0o644); err != nil {
				return fmt.Errorf("write chain: %w", err)
			}
			printer.Info("Chain saved to %s", chainOut)
		}

		chain, err := client.GetCertChain(ctx, cert.ID)
		if err == nil {
			if err := os.WriteFile(fullchainOut, []byte(chain.FullChainPem), 0o644); err != nil {
				return fmt.Errorf("write fullchain: %w", err)
			}
			printer.Info("Full chain saved to %s", fullchainOut)
		}
	}

	printer.JSON(cert)
	printer.Success("Certificate %d issued", cert.ID)
	return nil
}
