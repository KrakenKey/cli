// Package output handles text and JSON formatted output for the CLI.
// In text mode, output is colored and human-readable.
// In JSON mode, all output is machine-readable JSON on stdout; spinners and
// interactive prompts are suppressed.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorBlue  = "\033[34m"
	colorBold  = "\033[1m"
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

func (p *Printer) color(c, s string) string {
	if p.noColor {
		return s
	}
	return c + s + colorReset
}

// Success prints a success message prefixed with ✓ (text mode only).
func (p *Printer) Success(msg string, args ...any) {
	if p.IsJSON() {
		return
	}
	fmt.Fprint(p.w, p.color(colorGreen, "✓")+" "+fmt.Sprintf(msg, args...)+"\n")
}

// Error prints an error message to stderr. In JSON mode it emits {"error":"..."}.
func (p *Printer) Error(msg string, args ...any) {
	text := fmt.Sprintf(msg, args...)
	if p.IsJSON() {
		data, _ := json.Marshal(map[string]string{"error": text})
		fmt.Fprintln(p.errW, string(data))
		return
	}
	fmt.Fprint(p.errW, p.color(colorRed, "Error:")+" "+text+"\n")
}

// Info prints an informational message prefixed with • (text mode only).
func (p *Printer) Info(msg string, args ...any) {
	if p.IsJSON() {
		return
	}
	fmt.Fprint(p.w, p.color(colorBlue, "•")+" "+fmt.Sprintf(msg, args...)+"\n")
}

// Println prints a plain line (text mode only).
func (p *Printer) Println(msg string, args ...any) {
	if p.IsJSON() {
		return
	}
	fmt.Fprint(p.w, fmt.Sprintf(msg, args...)+"\n")
}

// Printf prints a formatted string (text mode only).
func (p *Printer) Printf(format string, args ...any) {
	if p.IsJSON() {
		return
	}
	fmt.Fprintf(p.w, format, args...)
}

// JSON marshals v as indented JSON and writes it to stdout.
func (p *Printer) JSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(p.errW, `{"error":"failed to marshal JSON"}`+"\n")
		return
	}
	fmt.Fprintln(p.w, string(data))
}

// Table prints an aligned text table (text mode only).
// headers and each row must have the same number of columns.
func (p *Printer) Table(headers []string, rows [][]string) {
	if p.IsJSON() {
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Header row
	fmt.Fprintf(p.w, "  ")
	for i, h := range headers {
		fmt.Fprint(p.w, p.color(colorBold, fmt.Sprintf("%-*s", widths[i], h)))
		if i < len(headers)-1 {
			fmt.Fprintf(p.w, "   ")
		}
	}
	fmt.Fprintln(p.w)

	// Separator
	fmt.Fprintf(p.w, "  ")
	for i, w := range widths {
		fmt.Fprint(p.w, strings.Repeat("─", w))
		if i < len(widths)-1 {
			fmt.Fprintf(p.w, "   ")
		}
	}
	fmt.Fprintln(p.w)

	// Data rows
	for _, row := range rows {
		fmt.Fprintf(p.w, "  ")
		for i, cell := range row {
			if i < len(widths) {
				fmt.Fprintf(p.w, "%-*s", widths[i], cell)
				if i < len(row)-1 && i < len(widths)-1 {
					fmt.Fprintf(p.w, "   ")
				}
			}
		}
		fmt.Fprintln(p.w)
	}
}

// Spinner is a braille-animation spinner that writes to stderr.
// In JSON mode all Spinner methods are no-ops.
type Spinner struct {
	mu   sync.Mutex
	msg  string
	done chan struct{}
	wg   sync.WaitGroup
	w    io.Writer
	json bool
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// NewSpinner creates a spinner with the given initial message.
func (p *Printer) NewSpinner(msg string) *Spinner {
	return &Spinner{msg: msg, done: make(chan struct{}), w: p.errW, json: p.IsJSON()}
}

// Start begins the spinner animation in a background goroutine.
func (s *Spinner) Start() {
	if s.json {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		i := 0
		for {
			select {
			case <-s.done:
				fmt.Fprintf(s.w, "\r\033[K")
				return
			default:
				s.mu.Lock()
				msg := s.msg
				s.mu.Unlock()
				fmt.Fprintf(s.w, "\r%s %s", spinnerFrames[i%len(spinnerFrames)], msg)
				time.Sleep(80 * time.Millisecond)
				i++
			}
		}
	}()
}

// UpdateMsg changes the spinner message while it is running.
func (s *Spinner) UpdateMsg(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

// Stop halts the spinner and clears the line.
func (s *Spinner) Stop() {
	if s.json {
		return
	}
	close(s.done)
	s.wg.Wait()
}
