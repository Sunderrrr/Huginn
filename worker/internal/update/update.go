// Package update performs atomic, rollback-safe worker self-updates. The new
// binary is downloaded next to the current one, its SHA-256 is verified against
// the published checksums, then swapped in atomically. If the post-restart health
// check fails, the previous binary is restored. All download hosts (including
// redirect hops) are checked against an allowlist to prevent SSRF.
package update

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Spec describes a single update, as provided by the hub (already validated
// server-side; re-validated here).
type Spec struct {
	BinaryURL    string
	ChecksumsURL string
	AssetName    string
	Version      string
	BinaryPath   string
}

// Updater applies updates. Restart and HealthCheck are injectable for testing.
type Updater struct {
	HTTP           *http.Client
	AllowedDomains []string
	Restart        func(ctx context.Context) error
	HealthCheck    func(ctx context.Context) error
}

// ErrHostNotAllowed indicates an SSRF-blocked download host.
var ErrHostNotAllowed = errors.New("download host not in allowlist")

// NewUpdater builds an Updater whose HTTP client validates every redirect hop
// against the allowlist.
func NewUpdater(allowed []string, restart, health func(ctx context.Context) error) *Updater {
	u := &Updater{AllowedDomains: allowed, Restart: restart, HealthCheck: health}
	u.HTTP = &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return validateHost(req.URL, allowed)
		},
	}
	return u
}

// ValidateURL checks scheme and host against the allowlist.
func ValidateURL(raw string, allowed []string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	return validateHost(parsed, allowed)
}

func validateHost(u *url.URL, allowed []string) error {
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q must be https", ErrHostNotAllowed, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	for _, a := range allowed {
		if host == strings.ToLower(a) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrHostNotAllowed, host)
}

// Apply runs the full update with rollback on failure.
func (u *Updater) Apply(ctx context.Context, spec Spec) error {
	if err := ValidateURL(spec.BinaryURL, u.AllowedDomains); err != nil {
		return err
	}
	if err := ValidateURL(spec.ChecksumsURL, u.AllowedDomains); err != nil {
		return err
	}

	expected, err := u.fetchExpectedChecksum(ctx, spec.ChecksumsURL, spec.AssetName)
	if err != nil {
		return fmt.Errorf("checksum lookup: %w", err)
	}

	dir := filepath.Dir(spec.BinaryPath)
	tmp := filepath.Join(dir, ".huginn-worker.new")
	if err := u.download(ctx, spec.BinaryURL, tmp); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer os.Remove(tmp)

	sum, err := fileSHA256(tmp)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(sum), []byte(expected)) != 1 {
		return fmt.Errorf("checksum mismatch: got %s want %s", sum, expected)
	}
	if err := os.Chmod(tmp, 0o755); err != nil { //nolint:gosec // executable binary
		return err
	}

	// Keep a backup of the current binary for rollback.
	backup := spec.BinaryPath + ".bak"
	if err := copyFile(spec.BinaryPath, backup); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := os.Rename(tmp, spec.BinaryPath); err != nil {
		return fmt.Errorf("atomic swap: %w", err)
	}

	if err := u.restartAndHealth(ctx); err != nil {
		// Roll back to the previous binary and restart again.
		if rbErr := os.Rename(backup, spec.BinaryPath); rbErr != nil {
			return fmt.Errorf("update failed (%v) and rollback failed: %w", err, rbErr)
		}
		if u.Restart != nil {
			_ = u.Restart(ctx)
		}
		return fmt.Errorf("update health check failed, rolled back: %w", err)
	}

	os.Remove(backup)
	return nil
}

func (u *Updater) restartAndHealth(ctx context.Context) error {
	if u.Restart != nil {
		if err := u.Restart(ctx); err != nil {
			return err
		}
	}
	if u.HealthCheck != nil {
		return u.HealthCheck(ctx)
	}
	return nil
}

func (u *Updater) fetchExpectedChecksum(ctx context.Context, url, asset string) (string, error) {
	body, err := u.get(ctx, url)
	if err != nil {
		return "", err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// sha256sum format: "<hash>  <filename>"; match on basename.
		if filepath.Base(fields[1]) == asset {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %q", asset)
}

func (u *Updater) download(ctx context.Context, url, dest string) error {
	body, err := u.get(ctx, url)
	if err != nil {
		return err
	}
	defer body.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, body)
	return err
}

func (u *Updater) get(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	if err := ValidateURL(rawURL, u.AllowedDomains); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	return resp.Body, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is internally constructed
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // src is the current binary path
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) //nolint:gosec // executable
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
