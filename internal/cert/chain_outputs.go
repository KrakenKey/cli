package cert

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// chainOutputs describes where the intermediate chain and full chain of an
// issued certificate go, and whether the user asked for each file explicitly
// (--chain-out / --fullchain-out) rather than relying on the default path.
type chainOutputs struct {
	CertOut            string // where the leaf was saved, for error messages
	ChainOut           string
	FullchainOut       string
	ChainRequested     bool
	FullchainRequested bool
}

// saveChainFiles writes the intermediate chain and the full chain for an
// issued certificate whose leaf has already been saved.
//
// A file the user asked for that cannot be written is an error, so scripts
// that deploy the full chain do not carry on with a missing or stale file.
// The error says the leaf was saved and how to fetch the chain later. A file
// that was not asked for only produces a warning.
func saveChainFiles(ctx context.Context, client *api.Client, printer *output.Printer, c *api.TlsCert, paths chainOutputs) error {
	var errs []error

	if c.ChainPem != "" {
		if err := os.WriteFile(paths.ChainOut, []byte(c.ChainPem), 0o644); err != nil {
			return fmt.Errorf("write chain: %w", err)
		}
		printer.Info("Chain saved to %s", paths.ChainOut)
	} else if paths.ChainRequested {
		errs = append(errs, chainNotSavedError(c.ID, paths.CertOut, "intermediate chain", FormatChain, paths.ChainOut,
			errors.New("the API returned no intermediate chain")))
	}

	chain, err := client.GetCertChain(ctx, c.ID)
	switch {
	case err == nil:
		if err := os.WriteFile(paths.FullchainOut, []byte(chain.FullChainPem), 0o644); err != nil {
			return fmt.Errorf("write fullchain: %w", err)
		}
		printer.Info("Full chain saved to %s", paths.FullchainOut)
	case paths.FullchainRequested:
		errs = append(errs, chainNotSavedError(c.ID, paths.CertOut, "full chain", FormatFullchain, paths.FullchainOut, err))
	default:
		printer.Warn("full chain not saved, could not fetch it: %s. Run `krakenkey cert download %d --format %s` to fetch it later",
			err, c.ID, FormatFullchain)
	}

	return errors.Join(errs...)
}

func chainNotSavedError(id int, certOut, what, format, path string, cause error) error {
	return fmt.Errorf("certificate %d was saved to %s, but the %s was not: %w. Run `krakenkey cert download %d --format %s --out %s` to fetch it later",
		id, certOut, what, cause, id, format, path)
}
