// Package config holds the worker's build version, default paths, and on-disk
// state (hub URL + per-worker credentials). The state file is written 0600.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Version is set at build time via -ldflags. It reports the installed worker
// version to the hub on every heartbeat.
var Version = "dev"

// Default filesystem locations. Overridable via flags / env for tests.
const (
	DefaultStateDir   = "/etc/huginn"
	DefaultStateFile  = "worker.json"
	DefaultBinaryPath = "/usr/local/bin/huginn-worker"
)

// DefaultAllowedReleaseDomains is the worker-side SSRF allowlist for update
// downloads (defense in depth; the hub also validates).
var DefaultAllowedReleaseDomains = []string{"github.com", "objects.githubusercontent.com"}

// State is the persisted worker configuration and identity.
type State struct {
	HubURL                 string   `json:"hub_url"`
	WorkerID               string   `json:"worker_id"`
	WorkerSecret           string   `json:"worker_secret"`
	AllowedReleaseDomains  []string `json:"allowed_release_domains,omitempty"`
	BinaryPath             string   `json:"binary_path,omitempty"`
	AllowInsecureTransport bool     `json:"allow_insecure_transport,omitempty"`
}

// AllowedDomains returns the configured allowlist or the built-in default.
func (s *State) AllowedDomains() []string {
	if len(s.AllowedReleaseDomains) > 0 {
		return s.AllowedReleaseDomains
	}
	return DefaultAllowedReleaseDomains
}

// BinaryLocation returns the configured binary path or the default.
func (s *State) BinaryLocation() string {
	if s.BinaryPath != "" {
		return s.BinaryPath
	}
	return DefaultBinaryPath
}

// StatePath returns the state file path for a given directory.
func StatePath(dir string) string {
	if dir == "" {
		dir = DefaultStateDir
	}
	return filepath.Join(dir, DefaultStateFile)
}

// Load reads worker state from path.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	return &s, nil
}

// Save writes worker state atomically with 0600 permissions. Credentials must
// never be world-readable.
func Save(path string, s *State) error {
	if s.WorkerID == "" || s.WorkerSecret == "" {
		return errors.New("refusing to save state without worker identity")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
