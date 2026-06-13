package whitelist

import (
	"errors"
	"testing"
)

func TestKnownActionsBuildArgv(t *testing.T) {
	argv, err := BuildArgv("status", nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(argv) == 0 {
		t.Fatalf("status produced empty argv")
	}
}

func TestUnknownActionRejected(t *testing.T) {
	_, err := BuildArgv("rm_rf_root", nil)
	if !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("expected ErrUnknownAction, got %v", err)
	}
}

func TestRestartServiceBuildsExpectedArgv(t *testing.T) {
	argv, err := BuildArgv("restart_service", map[string]string{"service": "nginx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"systemctl", "restart", "nginx"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}

func TestRestartServiceRejectsInjection(t *testing.T) {
	// Each of these must be rejected: a malicious service name can never reach
	// a shell, and the validator refuses metacharacters outright.
	for _, evil := range []string{
		"nginx; reboot", "a b", "$(reboot)", "x`id`", "../../etc", "a|b", "", "a&b",
	} {
		if _, err := BuildArgv("restart_service", map[string]string{"service": evil}); err == nil {
			t.Fatalf("expected rejection for service=%q", evil)
		}
	}
}

func TestRestartServiceRequiresParam(t *testing.T) {
	if _, err := BuildArgv("restart_service", nil); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("expected ErrInvalidParam, got %v", err)
	}
}

func TestKnown(t *testing.T) {
	if !Known("metrics") {
		t.Fatalf("metrics should be known")
	}
	if Known("nope") {
		t.Fatalf("nope should not be known")
	}
}
