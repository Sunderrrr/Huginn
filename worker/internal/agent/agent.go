// Package agent runs the worker's main loop: it heartbeats the hub, pulls tasks,
// executes them (whitelisted actions via fixed argv, free commands via a shell
// ONLY in the hub-gated unrestricted mode, updates via the update package), and
// reports results. Pulling over an outbound connection keeps workers usable
// behind NAT.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Sunderrrr/Huginn/worker/internal/config"
	wexec "github.com/Sunderrrr/Huginn/worker/internal/exec"
	"github.com/Sunderrrr/Huginn/worker/internal/hubclient"
	"github.com/Sunderrrr/Huginn/worker/internal/update"
	"github.com/Sunderrrr/Huginn/worker/internal/whitelist"
)

// Agent owns the worker run loop and its dependencies (injectable for tests).
type Agent struct {
	Client            *hubclient.Client
	Runner            wexec.Runner
	State             *config.State
	HeartbeatInterval time.Duration
	PollInterval      time.Duration
	// LongPollSeconds is how long the hub holds an empty /tasks/next request.
	// Tasks are picked up the instant they are queued; 0 disables long-polling
	// (falls back to immediate-return polling with PollInterval backoff).
	LongPollSeconds int
	Logger          *slog.Logger

	// HealthCommand validates a freshly swapped binary (defaults to running
	// "<binary> healthcheck"). Injectable for tests.
	HealthCommand func(ctx context.Context, binaryPath string) error

	// RetryBackoffBase is the first delay between retries of an idempotent action
	// (doubled each attempt, capped at 8s). Defaults to 1s; small in tests.
	RetryBackoffBase time.Duration

	// mu guards execMode, which the heartbeat goroutine writes and the poll loop
	// reads concurrently.
	mu sync.Mutex
	// execMode is the VM's exec mode as last reported by the hub heartbeat. The
	// worker refuses free-command tasks unless this is "unrestricted" — a local
	// defense-in-depth gate so the hub alone cannot enable arbitrary shell.
	execMode string
}

func (a *Agent) setExecMode(mode string) {
	a.mu.Lock()
	a.execMode = mode
	a.mu.Unlock()
}

func (a *Agent) getExecMode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.execMode
}

// New builds an Agent with sensible defaults.
func New(client *hubclient.Client, state *config.State, logger *slog.Logger) *Agent {
	return &Agent{
		Client:            client,
		Runner:            wexec.CommandRunner{},
		State:             state,
		HeartbeatInterval: 30 * time.Second,
		PollInterval:      2 * time.Second,
		LongPollSeconds:   25,
		Logger:            logger,
		HealthCommand:     defaultHealthCommand,
		RetryBackoffBase:  time.Second,
	}
}

// maxIdlePollInterval caps the backoff applied when the queue is empty, so an
// idle worker does not hammer the hub.
const maxIdlePollInterval = 30 * time.Second

// Run loops until ctx is cancelled or an update requires a restart (in which case
// it returns nil so the supervisor can relaunch the new binary).
//
// When LongPollSeconds > 0 the hub holds an empty /tasks/next request open until
// a task is queued (or the wait elapses), so tasks are picked up near-instantly
// and an idle worker does not busy-poll. When it is 0, the loop falls back to
// immediate-return polling with exponential backoff.
func (a *Agent) Run(ctx context.Context) error {
	hbTicker := time.NewTicker(a.HeartbeatInterval)
	defer hbTicker.Stop()
	a.heartbeat(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hbTicker.C:
				a.heartbeat(ctx)
			}
		}
	}()

	interval := a.PollInterval
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		didWork, restart := a.pollOnce(ctx)
		if restart {
			a.Logger.Info("update applied; exiting for supervised restart")
			return nil
		}
		if a.LongPollSeconds > 0 {
			// The hub already blocked for us; loop straight back unless we hit an
			// error (didWork is false on both "no task" and "error"), in which case
			// a short pause avoids a tight error loop.
			if !didWork {
				a.sleep(ctx, a.PollInterval)
			}
			continue
		}
		// Immediate-return polling: back off when idle.
		if didWork {
			interval = a.PollInterval
		} else if interval < maxIdlePollInterval {
			interval *= 2
			if interval > maxIdlePollInterval {
				interval = maxIdlePollInterval
			}
		}
		a.sleep(ctx, interval)
	}
}

func (a *Agent) heartbeat(ctx context.Context) {
	resp, err := a.Client.Heartbeat(ctx, hubclient.HeartbeatRequest{WorkerVersion: config.Version})
	if err != nil {
		a.Logger.Warn("heartbeat failed", "err", err)
		return
	}
	a.setExecMode(resp.ExecMode)
	// Merge hub-provided release domains into the built-in allowlist. The hub can
	// ADD domains but never remove the built-in defaults, and any domain it pushes
	// must pass local validation (no localhost/.local/.internal). This keeps the
	// defense-in-depth model: a compromised hub cannot point the worker at
	// arbitrary internal hosts.
	if len(resp.AllowedReleaseDomains) > 0 {
		merged := append([]string{}, config.DefaultAllowedReleaseDomains...)
		seen := map[string]bool{}
		for _, d := range merged {
			seen[d] = true
		}
		for _, d := range resp.AllowedReleaseDomains {
			if !seen[d] && isSafeReleaseDomain(d) {
				merged = append(merged, d)
				seen[d] = true
			}
		}
		a.mu.Lock()
		a.State.AllowedReleaseDomains = merged
		a.mu.Unlock()
	}
}

// isSafeReleaseDomain rejects loopback/link-local/internal names a malicious hub
// might try to push into the worker's allowlist.
func isSafeReleaseDomain(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || strings.Contains(h, "/") {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return false
	}
	// Block known dangerous IP literals.
	switch h {
	case "169.254.169.254", "127.0.0.1", "0.0.0.0", "::1":
		return false
	}
	return true
}

// pollOnce fetches and runs at most one task. It returns whether it handled a
// task (for poll backoff) and whether a restart is needed (after an update).
func (a *Agent) pollOnce(ctx context.Context) (didWork bool, restart bool) {
	task, err := a.Client.PollNextTask(ctx, a.LongPollSeconds)
	if err != nil {
		a.Logger.Warn("poll failed", "err", err)
		return false, false
	}
	if task == nil {
		return false, false
	}
	a.Logger.Info("running task", "id", task.ID, "type", task.Type)
	result, restart := a.dispatch(ctx, task)
	if err := a.Client.SubmitResult(ctx, task.ID, result); err != nil {
		a.Logger.Warn("submit result failed", "id", task.ID, "err", err)
		return true, false
	}
	return true, restart
}

func (a *Agent) dispatch(ctx context.Context, task *hubclient.Task) (hubclient.TaskResult, bool) {
	switch task.Type {
	case "action":
		return a.runAction(ctx, task), false
	case "command":
		return a.runCommand(ctx, task), false
	case "update":
		return a.runUpdate(ctx, task)
	case "uninstall":
		return a.runUninstall(ctx, task), false
	default:
		return failure("unknown task type: " + task.Type), false
	}
}

// maxActionAttempts bounds how many times an idempotent action is tried before
// its last result is reported. Non-idempotent actions are always tried once.
const maxActionAttempts = 3

func (a *Agent) runAction(ctx context.Context, task *hubclient.Task) hubclient.TaskResult {
	// A name the worker doesn't know built-in is an admin-defined custom command:
	// its fixed argv rides in the task payload, gated on the VM's exec mode.
	if !whitelist.Known(task.ActionName) {
		return a.runCustom(ctx, task)
	}
	argv, err := whitelist.BuildArgv(task.ActionName, stringParams(task.Payload["params"]))
	if err != nil {
		return failure(err.Error())
	}
	timeout := taskTimeout(task.Payload)
	attempts := 1
	if whitelist.Idempotent(task.ActionName) {
		attempts = maxActionAttempts
	}

	var result hubclient.TaskResult
	for attempt := 1; ; attempt++ {
		if res, err := a.Runner.Run(ctx, argv, timeout, 0); err != nil {
			result = failure(err.Error())
		} else {
			result = fromExecResult(res)
		}
		if result.Status == "succeeded" || attempt >= attempts {
			return result
		}
		// Transient failure on an idempotent action (e.g. an apt mirror briefly
		// down): back off and retry. Re-running is side-effect-free here.
		a.Logger.Warn("idempotent action failed; retrying",
			"id", task.ID, "action", task.ActionName,
			"attempt", attempt, "status", result.Status)
		if !a.sleep(ctx, a.retryBackoff(attempt)) {
			return result // context cancelled — report what we have
		}
	}
}

// retryBackoff returns an exponential delay (base, 2×base, 4×base…) capped at 8s.
func (a *Agent) retryBackoff(attempt int) time.Duration {
	base := a.RetryBackoffBase
	if base <= 0 {
		base = time.Second
	}
	d := base << (attempt - 1)
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}

func (a *Agent) runCommand(ctx context.Context, task *hubclient.Task) hubclient.TaskResult {
	// Local defense in depth: even though the hub gates command tasks on the VM's
	// unrestricted mode, the worker independently refuses to run a shell unless it
	// has itself observed unrestricted mode via heartbeat.
	if a.getExecMode() != "unrestricted" {
		return failure("worker refused free command: unrestricted mode not enabled")
	}
	command, _ := task.Payload["command"].(string)
	if command == "" {
		return failure("empty command")
	}
	// Free-command mode is the explicit, hub-gated, audited "unrestricted" path;
	// using a shell here is intentional. The whitelist path never does this.
	argv := []string{"sh", "-c", command}
	res, err := a.Runner.Run(ctx, argv, taskTimeout(task.Payload), 0)
	if err != nil {
		return failure(err.Error())
	}
	return fromExecResult(res)
}

// runCustom runs an admin-defined custom command: an ordered list of fixed argv
// vectors supplied by the hub in the task payload, each executed WITHOUT a shell.
// Commands run in sequence and stop at the first failure; the combined output is
// reported. Like free commands, the worker independently gates this on having
// observed 'custom' (or 'unrestricted') exec mode — the hub alone cannot run it.
func (a *Agent) runCustom(ctx context.Context, task *hubclient.Task) hubclient.TaskResult {
	if mode := a.getExecMode(); mode != "custom" && mode != "unrestricted" {
		return failure("worker refused custom command: custom mode not enabled")
	}
	commands := argvList(task.Payload["commands"])
	if len(commands) == 0 {
		return failure("custom command has no commands")
	}
	timeout := taskTimeout(task.Payload)
	var stdout, stderr strings.Builder
	for i, argv := range commands {
		if len(argv) == 0 {
			continue
		}
		res, err := a.Runner.Run(ctx, argv, timeout, 0)
		if err != nil {
			stderr.WriteString(err.Error())
			return customResult("failed", nil, stdout.String(), stderr.String())
		}
		// Label each step so a multi-command result is readable.
		fmt.Fprintf(&stdout, "$ %s\n", strings.Join(argv, " "))
		stdout.WriteString(res.Stdout)
		stderr.WriteString(res.Stderr)
		if res.TimedOut {
			return customResult("timeout", &res.ExitCode, stdout.String(), stderr.String())
		}
		if res.ExitCode != 0 {
			// Stop at the first failing command (sequential, fail-fast).
			fmt.Fprintf(&stderr, "command %d/%d failed (exit %d)\n", i+1, len(commands), res.ExitCode)
			return customResult("failed", &res.ExitCode, stdout.String(), stderr.String())
		}
	}
	zero := 0
	return customResult("succeeded", &zero, stdout.String(), stderr.String())
}

func customResult(status string, exit *int, stdout, stderr string) hubclient.TaskResult {
	return hubclient.TaskResult{Status: status, ExitCode: exit, Stdout: stdout, Stderr: stderr}
}

func (a *Agent) runUpdate(ctx context.Context, task *hubclient.Task) (hubclient.TaskResult, bool) {
	spec := update.Spec{
		BinaryURL:    asString(task.Payload["binary_url"]),
		ChecksumsURL: asString(task.Payload["checksums_url"]),
		AssetName:    asString(task.Payload["asset_name"]),
		Version:      asString(task.Payload["target_version"]),
		BinaryPath:   a.State.BinaryLocation(),
	}
	health := func(c context.Context) error { return a.HealthCommand(c, spec.BinaryPath) }
	a.mu.Lock()
	allowedDomains := a.State.AllowedDomains()
	a.mu.Unlock()
	updater := update.NewUpdater(allowedDomains, nil, health)
	if err := updater.Apply(ctx, spec); err != nil {
		return failure("update failed: " + err.Error()), false
	}
	return hubclient.TaskResult{Status: "succeeded", ExitCode: intPtr(0),
		Stdout: "updated to " + spec.Version}, true
}

// runUninstall removes the worker service and binary from the host.
// This is a best-effort cleanup triggered before VM revocation.
// After reporting success, the worker should exit (the service will be gone).
func (a *Agent) runUninstall(ctx context.Context, task *hubclient.Task) hubclient.TaskResult {
	a.Logger.Info("uninstall requested — removing worker service")

	// 1. Stop and disable the systemd service (ignore errors — may already be stopped)
	_ = exec.CommandContext(ctx, "systemctl", "stop", "huginn-worker").Run()
	_ = exec.CommandContext(ctx, "systemctl", "disable", "huginn-worker").Run()

	// 2. Remove the systemd unit file
	_ = os.Remove("/etc/systemd/system/huginn-worker.service")

	// 3. Reload systemd daemon
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()

	// 4. Remove the binary
	binaryPath := a.State.BinaryLocation()
	_ = os.Remove(binaryPath)

	// 5. Remove the state directory (config, secrets)
	_ = os.RemoveAll(a.State.StateDir())

	a.Logger.Info("uninstall complete — worker will exit after reporting result")
	return hubclient.TaskResult{
		Status:   "succeeded",
		ExitCode: intPtr(0),
		Stdout:   "worker service removed, binary and state cleaned up",
	}
}

// sleep waits for d or until ctx is cancelled. It returns true if the full
// duration elapsed, false if ctx was cancelled first.
func (a *Agent) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// --- helpers ---

func defaultHealthCommand(ctx context.Context, binaryPath string) error {
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(c, binaryPath, "healthcheck").Run()
}

func fromExecResult(res wexec.Result) hubclient.TaskResult {
	status := "succeeded"
	if res.TimedOut {
		status = "timeout"
	} else if res.ExitCode != 0 {
		status = "failed"
	}
	code := res.ExitCode
	return hubclient.TaskResult{
		Status:   status,
		ExitCode: &code,
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
	}
}

func failure(msg string) hubclient.TaskResult {
	return hubclient.TaskResult{Status: "failed", Error: msg}
}

func taskTimeout(payload map[string]any) time.Duration {
	if v, ok := payload["timeout"].(float64); ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	return 60 * time.Second
}

func stringParams(v any) map[string]string {
	out := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

// stringSlice extracts a []string from a JSON array payload field (e.g. argv).
func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// argvList extracts a [][]string (list of argv vectors) from a JSON
// array-of-arrays payload field (e.g. a custom action's commands).
func argvList(v any) [][]string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([][]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, stringSlice(e))
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func intPtr(i int) *int { return &i }
