package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := StatePath(dir)
	in := &State{HubURL: "https://hub.example.com", WorkerID: "w1", WorkerSecret: "s3cr3t"}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.WorkerID != "w1" || out.WorkerSecret != "s3cr3t" || out.HubURL != in.HubURL {
		t.Fatalf("roundtrip mismatch: %+v", out)
	}
}

func TestSaveSets0600Permissions(t *testing.T) {
	dir := t.TempDir()
	path := StatePath(dir)
	if err := Save(path, &State{HubURL: "h", WorkerID: "w", WorkerSecret: "s"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permissions = %o, want 600 (secrets must not be world-readable)", perm)
	}
}

func TestSaveRefusesEmptyIdentity(t *testing.T) {
	if err := Save(StatePath(t.TempDir()), &State{HubURL: "h"}); err == nil {
		t.Fatalf("expected refusal to save without identity")
	}
}

func TestAllowedDomainsDefault(t *testing.T) {
	s := &State{}
	if len(s.AllowedDomains()) == 0 {
		t.Fatalf("expected default allowlist")
	}
	s.AllowedReleaseDomains = []string{"only.example.com"}
	if got := s.AllowedDomains(); len(got) != 1 || got[0] != "only.example.com" {
		t.Fatalf("override not respected: %v", got)
	}
}

func TestBinaryLocationDefault(t *testing.T) {
	s := &State{}
	if s.BinaryLocation() != DefaultBinaryPath {
		t.Fatalf("expected default binary path")
	}
	s.BinaryPath = filepath.Join("/opt", "huginn")
	if s.BinaryLocation() != "/opt/huginn" {
		t.Fatalf("override not respected")
	}
}
