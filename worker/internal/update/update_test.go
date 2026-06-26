package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const assetName = "huginn-worker-linux-amd64"

// newReleaseServer serves a fake binary and its checksums over TLS.
func newReleaseServer(t *testing.T, binary []byte, checksum string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(binary)
	})
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", checksum, assetName)
	})
	return httptest.NewTLSServer(mux)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func writeCurrentBinary(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "huginn-worker")
	old := []byte("OLD-BINARY")
	if err := os.WriteFile(path, old, 0o755); err != nil {
		t.Fatal(err)
	}
	return path, old
}

func newTestUpdater(ts *httptest.Server, health func(context.Context) error) *Updater {
	return &Updater{
		HTTP:           ts.Client(),
		AllowedDomains: []string{"127.0.0.1"},
		HealthCheck:    health,
	}
}

func TestApplySuccessSwapsBinary(t *testing.T) {
	newBin := []byte("NEW-BINARY-CONTENT")
	ts := newReleaseServer(t, newBin, sha256Hex(newBin))
	defer ts.Close()

	path, _ := writeCurrentBinary(t)
	u := newTestUpdater(ts, func(context.Context) error { return nil })

	err := u.Apply(context.Background(), Spec{
		BinaryURL:    ts.URL + "/bin",
		ChecksumsURL: ts.URL + "/checksums.txt",
		AssetName:    assetName,
		Version:      "v1.2.3",
		BinaryPath:   path,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(newBin) {
		t.Fatalf("binary = %q, want swapped content", got)
	}
	// Backup must be cleaned up on success.
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("backup file should be removed on success")
	}
}

func TestApplyChecksumMismatchKeepsOldBinary(t *testing.T) {
	newBin := []byte("NEW-BINARY-CONTENT")
	ts := newReleaseServer(t, newBin, sha256Hex([]byte("WRONG"))) // bad checksum
	defer ts.Close()

	path, old := writeCurrentBinary(t)
	u := newTestUpdater(ts, func(context.Context) error { return nil })

	err := u.Apply(context.Background(), Spec{
		BinaryURL:    ts.URL + "/bin",
		ChecksumsURL: ts.URL + "/checksums.txt",
		AssetName:    assetName,
		BinaryPath:   path,
	})
	if err == nil {
		t.Fatalf("expected checksum mismatch error")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(old) {
		t.Fatalf("old binary should be untouched on checksum failure")
	}
}

func TestApplyRollsBackOnHealthFailure(t *testing.T) {
	newBin := []byte("NEW-BINARY-CONTENT")
	ts := newReleaseServer(t, newBin, sha256Hex(newBin))
	defer ts.Close()

	path, old := writeCurrentBinary(t)
	u := newTestUpdater(ts, func(context.Context) error {
		return errors.New("new binary is unhealthy")
	})

	err := u.Apply(context.Background(), Spec{
		BinaryURL:    ts.URL + "/bin",
		ChecksumsURL: ts.URL + "/checksums.txt",
		AssetName:    assetName,
		BinaryPath:   path,
	})
	if err == nil {
		t.Fatalf("expected health-check failure error")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(old) {
		t.Fatalf("binary should be rolled back to old content, got %q", got)
	}
}

func TestApplyRejectsDisallowedHost(t *testing.T) {
	u := &Updater{AllowedDomains: []string{"github.com"}, HTTP: http.DefaultClient}
	err := u.Apply(context.Background(), Spec{
		BinaryURL:    "https://evil.example.com/bin",
		ChecksumsURL: "https://github.com/x/checksums.txt",
		AssetName:    assetName,
		BinaryPath:   "/tmp/whatever",
	})
	if !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("expected ErrHostNotAllowed, got %v", err)
	}
}

func TestValidateURL(t *testing.T) {
	allowed := []string{"github.com"}
	if err := ValidateURL("https://github.com/x", allowed); err != nil {
		t.Fatalf("github.com should be allowed: %v", err)
	}
	if err := ValidateURL("http://github.com/x", allowed); err == nil {
		t.Fatalf("http should be rejected")
	}
	if err := ValidateURL("https://evil.com/x", allowed); err == nil {
		t.Fatalf("evil.com should be rejected")
	}
}
