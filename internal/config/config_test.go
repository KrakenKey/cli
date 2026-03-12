package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/krakenkey/cli/internal/config"
)

// withTempConfigDir sets XDG_CONFIG_HOME to a temp dir for the duration of t.
func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func TestLoad_Defaults(t *testing.T) {
	withTempConfigDir(t)
	// Clear env vars that might be set in the shell.
	t.Setenv("KK_API_URL", "")
	t.Setenv("KK_API_KEY", "")
	t.Setenv("KK_OUTPUT", "")

	cfg, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIURL != "https://api.krakenkey.io" {
		t.Errorf("APIURL = %q, want default", cfg.APIURL)
	}
	if cfg.Output != "text" {
		t.Errorf("Output = %q, want text", cfg.Output)
	}
	if cfg.APIKey != "" {
		t.Errorf("APIKey = %q, want empty", cfg.APIKey)
	}
}

func TestLoad_EnvOverridesDefault(t *testing.T) {
	withTempConfigDir(t)
	t.Setenv("KK_API_URL", "https://staging.example.com")
	t.Setenv("KK_API_KEY", "kk_env_key")
	t.Setenv("KK_OUTPUT", "json")

	cfg, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIURL != "https://staging.example.com" {
		t.Errorf("APIURL = %q, want env value", cfg.APIURL)
	}
	if cfg.APIKey != "kk_env_key" {
		t.Errorf("APIKey = %q, want env value", cfg.APIKey)
	}
	if cfg.Output != "json" {
		t.Errorf("Output = %q, want json", cfg.Output)
	}
}

func TestLoad_FlagsOverrideEnv(t *testing.T) {
	withTempConfigDir(t)
	t.Setenv("KK_API_KEY", "kk_env_key")

	cfg, err := config.Load(config.Flags{APIKey: "kk_flag_key"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "kk_flag_key" {
		t.Errorf("APIKey = %q, want flag value", cfg.APIKey)
	}
}

func TestLoad_FileOverridesDefault(t *testing.T) {
	withTempConfigDir(t)
	t.Setenv("KK_API_URL", "")
	t.Setenv("KK_API_KEY", "")
	t.Setenv("KK_OUTPUT", "")

	if err := config.Save("https://file.example.com", "kk_file_key", "json"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIURL != "https://file.example.com" {
		t.Errorf("APIURL = %q, want file value", cfg.APIURL)
	}
	if cfg.APIKey != "kk_file_key" {
		t.Errorf("APIKey = %q, want file value", cfg.APIKey)
	}
}

func TestSave_CreatesFileWith0600(t *testing.T) {
	withTempConfigDir(t)

	if err := config.Save("", "kk_test", ""); err != nil {
		t.Fatalf("Save: %v", err)
	}

	configFile := filepath.Join(config.ConfigDir(), "config.yaml")
	info, err := os.Stat(configFile)
	if err != nil {
		t.Fatalf("Stat config file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file permissions = %o, want 0600", perm)
	}
}

func TestSave_PreservesExistingValues(t *testing.T) {
	withTempConfigDir(t)
	t.Setenv("KK_API_URL", "")
	t.Setenv("KK_API_KEY", "")
	t.Setenv("KK_OUTPUT", "")

	// Save initial values.
	if err := config.Save("https://api.example.com", "kk_key1", "text"); err != nil {
		t.Fatalf("Save initial: %v", err)
	}

	// Save only the API key — other fields must be preserved.
	if err := config.Save("", "kk_key2", ""); err != nil {
		t.Fatalf("Save update: %v", err)
	}

	cfg, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIURL != "https://api.example.com" {
		t.Errorf("APIURL = %q, want preserved value", cfg.APIURL)
	}
	if cfg.APIKey != "kk_key2" {
		t.Errorf("APIKey = %q, want updated value", cfg.APIKey)
	}
	if cfg.Output != "text" {
		t.Errorf("Output = %q, want preserved value", cfg.Output)
	}
}

func TestRemoveAPIKey(t *testing.T) {
	withTempConfigDir(t)
	t.Setenv("KK_API_URL", "")
	t.Setenv("KK_API_KEY", "")
	t.Setenv("KK_OUTPUT", "")

	if err := config.Save("", "kk_to_remove", ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := config.RemoveAPIKey(); err != nil {
		t.Fatalf("RemoveAPIKey: %v", err)
	}

	cfg, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "" {
		t.Errorf("APIKey = %q after removal, want empty", cfg.APIKey)
	}
}

func TestRemoveAPIKey_NonexistentFile(t *testing.T) {
	withTempConfigDir(t)
	// Should not return an error when the config file does not exist.
	if err := config.RemoveAPIKey(); err != nil {
		t.Errorf("RemoveAPIKey on missing file: %v", err)
	}
}

func TestConfigDir_RespectsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
	dir := config.ConfigDir()
	if dir != "/tmp/xdg-test/krakenkey" {
		t.Errorf("ConfigDir = %q, want /tmp/xdg-test/krakenkey", dir)
	}
}
