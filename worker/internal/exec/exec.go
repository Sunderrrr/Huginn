// Package exec runs commands as separated argv vectors. It NEVER interprets a
// shell: there is no `sh -c`, no string concatenation, and no metacharacter
// expansion. This is the core defense against command injection on the worker.
package exec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// DefaultMaxOutputBytes caps captured stdout/stderr to bound memory use.
const DefaultMaxOutputBytes = 1 << 20 // 1 MiB

// Result is the outcome of running a command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// Runner executes argv vectors. It is an interface so the agent can be tested
// with a fake.
type Runner interface {
	Run(ctx context.Context, argv []string, timeout time.Duration, maxOutput int) (Result, error)
}

// CommandRunner is the real, OS-backed Runner.
type CommandRunner struct{}

// Run executes argv[0] with argv[1:] as arguments — no shell is involved.
func (CommandRunner) Run(
	ctx context.Context, argv []string, timeout time.Duration, maxOutput int,
) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("empty argv")
	}
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutputBytes
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// exec.CommandContext does NOT invoke a shell; argv is passed verbatim.
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...) //nolint:gosec // argv is validated/whitelisted by the caller
	var stdout, stderr cappedBuffer
	stdout.limit = maxOutput
	stderr.limit = maxOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}
	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		// Command could not be started (e.g. binary not found).
		return res, err
	}
	return res, nil
}

// cappedBuffer is a bytes.Buffer that stops accepting data past a byte limit.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.limit - c.buf.Len()
	if remaining <= 0 {
		return len(p), nil // discard, but report success so the process keeps running
	}
	if len(p) > remaining {
		c.buf.Write(p[:remaining])
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) String() string { return c.buf.String() }
