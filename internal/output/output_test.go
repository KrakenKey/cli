package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/krakenkey/cli/internal/output"
)

func newPrinter(format string) (*output.Printer, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	p := output.NewWithWriters(format, true, out, errOut)
	return p, out, errOut
}

func TestPrinter_TextMode_Success(t *testing.T) {
	p, out, _ := newPrinter("text")
	p.Success("all done %s", "!")
	if !strings.Contains(out.String(), "all done !") {
		t.Errorf("Success output = %q, want to contain 'all done !'", out.String())
	}
}

func TestPrinter_TextMode_Println(t *testing.T) {
	p, out, _ := newPrinter("text")
	p.Println("hello %d", 42)
	if out.String() != "hello 42\n" {
		t.Errorf("Println = %q, want %q", out.String(), "hello 42\n")
	}
}

func TestPrinter_TextMode_Info(t *testing.T) {
	p, out, _ := newPrinter("text")
	p.Info("tip: %s", "do something")
	if !strings.Contains(out.String(), "tip: do something") {
		t.Errorf("Info output = %q, want to contain 'tip: do something'", out.String())
	}
}

func TestPrinter_TextMode_Error_WritesToStderr(t *testing.T) {
	p, out, errOut := newPrinter("text")
	p.Error("something went wrong")
	if out.Len() != 0 {
		t.Errorf("Error wrote to stdout: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "something went wrong") {
		t.Errorf("Error output = %q, want to contain 'something went wrong'", errOut.String())
	}
}

func TestPrinter_JSONMode_SuppressesText(t *testing.T) {
	p, out, _ := newPrinter("json")
	p.Success("this should not appear")
	p.Info("nor this")
	p.Println("nor this")
	if out.Len() != 0 {
		t.Errorf("JSON mode wrote text to stdout: %q", out.String())
	}
}

func TestPrinter_JSONMode_JSON(t *testing.T) {
	p, out, _ := newPrinter("json")
	type payload struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	p.JSON(payload{Name: "alice", Age: 30})

	var got payload
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal JSON output: %v\noutput: %s", err, out.String())
	}
	if got.Name != "alice" || got.Age != 30 {
		t.Errorf("got %+v, want {alice 30}", got)
	}
}

func TestPrinter_JSONMode_Error_WritesJSONToStderr(t *testing.T) {
	p, _, errOut := newPrinter("json")
	p.Error("oops %s", "bad")

	var got map[string]string
	if err := json.Unmarshal(errOut.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal error JSON: %v\noutput: %s", err, errOut.String())
	}
	if got["error"] != "oops bad" {
		t.Errorf("error field = %q, want %q", got["error"], "oops bad")
	}
}

func TestPrinter_Table_Alignment(t *testing.T) {
	p, out, _ := newPrinter("text")
	headers := []string{"ID", "Name", "Status"}
	rows := [][]string{
		{"1", "example.com", "issued"},
		{"42", "long-domain-name.example.com", "pending"},
	}
	p.Table(headers, rows)

	result := out.String()
	// Headers must appear
	for _, h := range headers {
		if !strings.Contains(result, h) {
			t.Errorf("table output missing header %q:\n%s", h, result)
		}
	}
	// All cell values must appear
	for _, row := range rows {
		for _, cell := range row {
			if !strings.Contains(result, cell) {
				t.Errorf("table output missing cell %q:\n%s", cell, result)
			}
		}
	}
}

func TestPrinter_Table_JSONMode_Suppressed(t *testing.T) {
	p, out, _ := newPrinter("json")
	p.Table([]string{"A", "B"}, [][]string{{"1", "2"}})
	if out.Len() != 0 {
		t.Errorf("Table wrote output in JSON mode: %q", out.String())
	}
}

func TestPrinter_IsJSON(t *testing.T) {
	pText, _, _ := newPrinter("text")
	if pText.IsJSON() {
		t.Error("text mode: IsJSON() = true, want false")
	}
	pJSON, _, _ := newPrinter("json")
	if !pJSON.IsJSON() {
		t.Error("json mode: IsJSON() = false, want true")
	}
}

func TestSpinner_StopsCleanly(t *testing.T) {
	p, _, _ := newPrinter("text")
	s := p.NewSpinner("working...")
	s.Start()
	s.UpdateMsg("still working...")
	s.Stop()
	// Just verify it doesn't deadlock or panic.
}

func TestSpinner_JSONMode_Noop(t *testing.T) {
	p, _, _ := newPrinter("json")
	s := p.NewSpinner("working...")
	s.Start()
	s.UpdateMsg("still working...")
	s.Stop()
	// Must not panic or block.
}
