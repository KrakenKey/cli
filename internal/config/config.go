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

// Load resolves configuration with the correct precedence.
func Load(flags Flags) (*Config, error) {
	panic("not implemented")
}

// Save writes the config file with 0600 permissions, creating the directory if needed.
func Save(apiURL, apiKey, output string) error {
	panic("not implemented")
}

// RemoveAPIKey clears the api_key field from the config file.
func RemoveAPIKey() error {
	panic("not implemented")
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
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	info, err := os.Stat(configPath())
	if err == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: config file %s has broad permissions (%s), consider chmod 600\n",
			configPath(), info.Mode().Perm())
	}
	return &fc, nil
}
