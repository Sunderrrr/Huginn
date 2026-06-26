package exec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunCapturesStdoutAndExitZero(t *testing.T) {
	res, err := CommandRunner{}.Run(context.Background(), []string{"echo", "hello"}, time.Second, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
	if strings.TrimSpace(res.Stdout) != "hello" {
		t.Fatalf("stdout = %q, want hello", res.Stdout)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	res, err := CommandRunner{}.Run(context.Background(), []string{"false"}, time.Second, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code")
	}
}

func TestRunTimeout(t *testing.T) {
	res, err := CommandRunner{}.Run(context.Background(), []string{"sleep", "5"}, 100*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true")
	}
}

func TestRunUnknownBinaryErrors(t *testing.T) {
	_, err := CommandRunner{}.Run(context.Background(), []string{"definitely-not-a-real-binary-xyz"}, time.Second, 0)
	if err == nil {
		t.Fatalf("expected error for missing binary")
	}
}

func TestRunEmptyArgv(t *testing.T) {
	_, err := CommandRunner{}.Run(context.Background(), nil, time.Second, 0)
	if err == nil {
		t.Fatalf("expected error for empty argv")
	}
}

func TestNoShellInterpretation(t *testing.T) {
	// If a shell were involved, "$(touch x)" would expand. Passed as a single
	// argv element to echo, it must be emitted literally.
	payload := "$(touch /tmp/should-not-exist); rm -rf /"
	res, err := CommandRunner{}.Run(context.Background(), []string{"echo", payload}, time.Second, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(res.Stdout) != payload {
		t.Fatalf("stdout = %q, want literal payload", res.Stdout)
	}
}

func TestOutputIsCapped(t *testing.T) {
	res, err := CommandRunner{}.Run(
		context.Background(),
		[]string{"sh", "-c", "yes abcdefgh | head -c 100000"},
		5*time.Second,
		1024,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Stdout) > 1024 {
		t.Fatalf("stdout length = %d, want <= 1024", len(res.Stdout))
	}
}
