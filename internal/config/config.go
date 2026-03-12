// Package config handles loading and saving CLI configuration.
// Precedence (highest to lowest): CLI flags > env vars > config file > defaults.
// Config file: ~/.config/krakenkey/config.yaml (XDG_CONFIG_HOME respected).
// File permissions: 0600. Broader permissions trigger a warning.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const defaultAPIURL = "https://api.krakenkey.io"

// Config holds the resolved configuration for a CLI invocation.
type Config struct {
	APIURL string
	APIKey string
	Output string // "text" or "json"
}

// Flags represents values provided via CLI flags for a given invocation.
type Flags struct {
	APIURL  string
	APIKey  string
	Output  string
	NoColor bool
	Verbose bool
}

type fileConfig struct {
	APIURL string `yaml:"api_url"`
	APIKey string `yaml:"api_key"`
	Output string `yaml:"output"`
}

// Load resolves configuration with the correct precedence:
// CLI flags > environment variables > config file > defaults.
func Load(flags Flags) (*Config, error) {
	cfg := &Config{
		APIURL: defaultAPIURL,
		Output: "text",
	}

	// Layer 1: config file (lowest priority after defaults)
	if fc, err := loadFile(); err == nil {
		if fc.APIURL != "" {
			cfg.APIURL = fc.APIURL
		}
		if fc.APIKey != "" {
			cfg.APIKey = fc.APIKey
		}
		if fc.Output != "" {
			cfg.Output = fc.Output
		}
	}

	// Layer 2: environment variables
	if v := os.Getenv("KK_API_URL"); v != "" {
		cfg.APIURL = v
	}
	if v := os.Getenv("KK_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("KK_OUTPUT"); v != "" {
		cfg.Output = v
	}

	// Layer 3: CLI flags (highest priority)
	if flags.APIURL != "" {
		cfg.APIURL = flags.APIURL
	}
	if flags.APIKey != "" {
		cfg.APIKey = flags.APIKey
	}
	if flags.Output != "" {
		cfg.Output = flags.Output
	}

	return cfg, nil
}

// Save writes the config file with 0600 permissions, creating the directory if needed.
// Only non-empty arguments overwrite existing values.
func Save(apiURL, apiKey, output string) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	existing := &fileConfig{}
	if fc, err := loadFile(); err == nil {
		existing = fc
	}
	if apiURL != "" {
		existing.APIURL = apiURL
	}
	if apiKey != "" {
		existing.APIKey = apiKey
	}
	if output != "" {
		existing.Output = output
	}

	data, err := yaml.Marshal(existing)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(configPath(), data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// RemoveAPIKey clears the api_key field from the config file.
func RemoveAPIKey() error {
	fc, err := loadFile()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	fc.APIKey = ""
	data, err := yaml.Marshal(fc)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(configPath(), data, 0o600)
}

// ConfigDir returns the krakenkey config directory, respecting XDG_CONFIG_HOME.
func ConfigDir() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "krakenkey")
}

func configPath() string {
	return filepath.Join(ConfigDir(), "config.yaml")
}

func loadFile() (*fileConfig, error) {
	path := configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	info, err := os.Stat(path)
	if err == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: config file %s has broad permissions (%s), consider chmod 600\n",
			path, info.Mode().Perm())
	}
	return &fc, nil
}
