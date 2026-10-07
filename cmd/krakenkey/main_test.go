package main

import (
	"io"
	"testing"

	flag "github.com/spf13/pflag"
)

func TestTriBoolFlagForms(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want *bool
	}{
		{"omitted", nil, nil},
		{"bare", []string{"--auto-renew"}, boolPtr(true)},
		{"true", []string{"--auto-renew=true"}, boolPtr(true)},
		{"false", []string{"--auto-renew=false"}, boolPtr(false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			var f triBoolFlag
			addTriBoolFlag(fs, &f, "auto-renew", "usage")
			wait := fs.Bool("wait", false, "")
			if err := fs.Parse(append(tt.args, "--wait")); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !*wait {
				t.Error("following flag was swallowed as the value")
			}
			switch {
			case tt.want == nil && f.val != nil:
				t.Errorf("got %v, want nil", *f.val)
			case tt.want != nil && (f.val == nil || *f.val != *tt.want):
				t.Errorf("got %v, want %v", f.val, *tt.want)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }
