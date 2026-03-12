// Package output handles text and JSON formatted output for the CLI.
// In text mode, output is colored and human-readable.
// In JSON mode, all output is machine-readable JSON on stdout; spinners and
// interactive prompts are suppressed.
package output

import (
	"io"
	"os"
)

// Printer formats and writes CLI output.
type Printer struct {
	format  string // "text" or "json"
	noColor bool
	w       io.Writer
	errW    io.Writer
}

// New creates a Printer writing to os.Stdout / os.Stderr.
// noColor is also forced on when the NO_COLOR env var is set.
func New(format string, noColor bool) *Printer {
	noColor = noColor || os.Getenv("NO_COLOR") != ""
	return &Printer{format: format, noColor: noColor, w: os.Stdout, errW: os.Stderr}
}

// NewWithWriters creates a Printer with custom writers (used in tests).
func NewWithWriters(format string, noColor bool, w, errW io.Writer) *Printer {
	return &Printer{format: format, noColor: noColor, w: w, errW: errW}
}

// IsJSON reports whether the printer is in JSON mode.
func (p *Printer) IsJSON() bool { return p.format == "json" }

// Success prints a success message prefixed with ✓ (text mode only).
func (p *Printer) Success(msg string, args ...any) { panic("not implemented") }

// Error prints an error message to stderr. In JSON mode it emits {"error":"..."}.
func (p *Printer) Error(msg string, args ...any) { panic("not implemented") }

// Info prints an informational message prefixed with • (text mode only).
func (p *Printer) Info(msg string, args ...any) { panic("not implemented") }

// Println prints a plain line (text mode only).
func (p *Printer) Println(msg string, args ...any) { panic("not implemented") }

// Printf prints a formatted string (text mode only).
func (p *Printer) Printf(format string, args ...any) { panic("not implemented") }

// JSON marshals v as indented JSON and writes it to stdout.
func (p *Printer) JSON(v any) { panic("not implemented") }

// Table prints an aligned text table (text mode only).
// headers and each row must have the same number of columns.
func (p *Printer) Table(headers []string, rows [][]string) { panic("not implemented") }

// Spinner is a braille-animation spinner that writes to stderr.
// In JSON mode all Spinner methods are no-ops.
type Spinner struct {
	msg  string
	w    io.Writer
	json bool
}

// NewSpinner creates a spinner with the given initial message.
func (p *Printer) NewSpinner(msg string) *Spinner {
	return &Spinner{msg: msg, w: p.errW, json: p.IsJSON()}
}

// Start begins the spinner animation in a background goroutine.
func (s *Spinner) Start() { panic("not implemented") }

// UpdateMsg changes the spinner message while it is running.
func (s *Spinner) UpdateMsg(msg string) { s.msg = msg }

// Stop halts the spinner and clears the line.
func (s *Spinner) Stop() { panic("not implemented") }
