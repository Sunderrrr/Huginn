package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sunderrrr/Huginn/worker/internal/config"
	wexec "github.com/Sunderrrr/Huginn/worker/internal/exec"
	"github.com/Sunderrrr/Huginn/worker/internal/hubclient"
)

// fakeRunner records the argv it was asked to run and returns a canned result.
type fakeRunner struct {
	gotArgv []string
	result  wexec.Result
	err     error
}

func (f *fakeRunner) Run(_ context.Context, argv []string, _ time.Duration, _ int) (wexec.Result, error) {
	f.gotArgv = argv
	return f.result, f.err
}

func newTestAgent(runner wexec.Runner) *Agent {
	return &Agent{
		Runner:           runner,
		State:            &config.State{},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetryBackoffBase: time.Millisecond, // keep retry tests fast
	}
}

// seqRunner returns a queued result per call (the last one repeats) and counts
// invocations — used to exercise the retry loop.
type seqRunner struct {
	results []wexec.Result
	calls   int
}

func (s *seqRunner) Run(_ context.Context, _ []string, _ time.Duration, _ int) (wexec.Result, error) {
	i := s.calls
	s.calls++
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	return s.results[i], nil
}

func TestIdempotentActionRetriesThenSucceeds(t *testing.T) {
	runner := &seqRunner{results: []wexec.Result{
		{ExitCode: 1, Stderr: "mirror down"}, // attempt 1: transient failure
		{ExitCode: 0, Stdout: "ok"},          // attempt 2: success
	}}
	a := newTestAgent(runner)
	task := &hubclient.Task{ID: "t", Type: "action", ActionName: "list_upgradable_packages", Payload: map[string]any{}}

	res := a.runAction(context.Background(), task)
	if res.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded after retry", res.Status)
	}
	if runner.calls != 2 {
		t.Fatalf("calls = %d, want 2 (one retry)", runner.calls)
	}
}

func TestIdempotentActionGivesUpAfterMaxAttempts(t *testing.T) {
	runner := &seqRunner{results: []wexec.Result{{ExitCode: 1, Stderr: "still down"}}}
	a := newTestAgent(runner)
	task := &hubclient.Task{ID: "t", Type: "action", ActionName: "status", Payload: map[string]any{}}

	res := a.runAction(context.Background(), task)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if runner.calls != maxActionAttempts {
		t.Fatalf("calls = %d, want %d", runner.calls, maxActionAttempts)
	}
}

func customTask(commands ...[]string) *hubclient.Task {
	cmds := make([]any, len(commands))
	for i, c := range commands {
		argv := make([]any, len(c))
		for j, s := range c {
			argv[j] = s
		}
		cmds[i] = argv
	}
	return &hubclient.Task{ID: "t", Type: "action", ActionName: "custom-x",
		Payload: map[string]any{"commands": cmds}}
}

func TestCustomCommandRunsSequenceInCustomMode(t *testing.T) {
	runner := &seqRunner{results: []wexec.Result{{ExitCode: 0}, {ExitCode: 0}}}
	a := newTestAgent(runner)
	a.setExecMode("custom")
	task := customTask([]string{"systemctl", "restart", "nginx"}, []string{"echo", "done"})

	res := a.runAction(context.Background(), task)
	if res.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", res.Status)
	}
	if runner.calls != 2 {
		t.Fatalf("calls = %d, want 2 (both commands ran)", runner.calls)
	}
}

func TestCustomCommandStopsAtFirstFailure(t *testing.T) {
	// First command fails → the second must NOT run.
	runner := &seqRunner{results: []wexec.Result{{ExitCode: 3, Stderr: "boom"}, {ExitCode: 0}}}
	a := newTestAgent(runner)
	a.setExecMode("custom")
	task := customTask([]string{"false"}, []string{"echo", "never"})

	res := a.runAction(context.Background(), task)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if runner.calls != 1 {
		t.Fatalf("calls = %d, want 1 (stop at first failure)", runner.calls)
	}
}

func TestCustomCommandRefusedOutsideCustomMode(t *testing.T) {
	runner := &fakeRunner{}
	a := newTestAgent(runner) // execMode defaults to "" (whitelist)
	task := customTask([]string{"systemctl", "restart", "nginx"})

	res := a.runAction(context.Background(), task)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if runner.gotArgv != nil {
		t.Fatalf("runner must not be invoked when custom mode is off")
	}
}

func TestNonIdempotentActionNotRetried(t *testing.T) {
	runner := &seqRunner{results: []wexec.Result{{ExitCode: 1, Stderr: "boom"}}}
	a := newTestAgent(runner)
	// apt_upgrade is mutating → must run exactly once even on failure.
	task := &hubclient.Task{ID: "t", Type: "action", ActionName: "apt_upgrade", Payload: map[string]any{}}

	res := a.runAction(context.Background(), task)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if runner.calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retry for mutating action)", runner.calls)
	}
}

func TestDispatchActionUsesWhitelistArgv(t *testing.T) {
	runner := &fakeRunner{result: wexec.Result{ExitCode: 0, Stdout: "linux"}}
	a := newTestAgent(runner)
	task := &hubclient.Task{ID: "t1", Type: "action", ActionName: "status", Payload: map[string]any{}}

	res, restart := a.dispatch(context.Background(), task)
	if restart {
		t.Fatalf("action should not request restart")
	}
	if res.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", res.Status)
	}
	want := []string{"uname", "-a"}
	if strings.Join(runner.gotArgv, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v, want %v", runner.gotArgv, want)
	}
}

func TestDispatchUnknownActionFails(t *testing.T) {
	runner := &fakeRunner{}
	a := newTestAgent(runner)
	task := &hubclient.Task{ID: "t1", Type: "action", ActionName: "nope", Payload: map[string]any{}}
	res, _ := a.dispatch(context.Background(), task)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if runner.gotArgv != nil {
		t.Fatalf("runner should not be invoked for unknown action")
	}
}

func TestDispatchCommandUsesShellWhenUnrestricted(t *testing.T) {
	// Free-command mode (hub-gated unrestricted) intentionally goes through a shell.
	runner := &fakeRunner{result: wexec.Result{ExitCode: 0}}
	a := newTestAgent(runner)
	a.execMode = "unrestricted"
	task := &hubclient.Task{
		ID: "t1", Type: "command",
		Payload: map[string]any{"command": "echo hi"},
	}
	a.dispatch(context.Background(), task)
	want := []string{"sh", "-c", "echo hi"}
	if strings.Join(runner.gotArgv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v, want %v", runner.gotArgv, want)
	}
}

func TestDispatchCommandRefusedWhenNotUnrestricted(t *testing.T) {
	// Defense in depth: the worker refuses shell commands unless it has itself
	// observed unrestricted mode, even if a command task arrives.
	runner := &fakeRunner{}
	a := newTestAgent(runner) // execMode defaults to "" (whitelist)
	task := &hubclient.Task{
		ID: "t1", Type: "command",
		Payload: map[string]any{"command": "echo hi"},
	}
	res, _ := a.dispatch(context.Background(), task)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if runner.gotArgv != nil {
		t.Fatalf("runner must not be invoked when unrestricted mode is off")
	}
}

func TestDispatchUnknownTypeFails(t *testing.T) {
	a := newTestAgent(&fakeRunner{})
	res, _ := a.dispatch(context.Background(), &hubclient.Task{ID: "t", Type: "mystery"})
	if res.Status != "failed" {
		t.Fatalf("expected failed for unknown type")
	}
}

func TestPollOnceRunsAndSubmitsResult(t *testing.T) {
	var submitted hubclient.TaskResult
	mux := http.NewServeMux()
	mux.HandleFunc("/api/worker/tasks/next", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"t1","type":"action","action_name":"status","payload":{}}`))
	})
	mux.HandleFunc("/api/worker/tasks/t1/result", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &submitted)
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, _ := hubclient.New(hubclient.Options{
		BaseURL: ts.URL, WorkerID: "vm", WorkerSecret: "s",
		AllowInsecure: true, HTTPClient: ts.Client(),
	})
	a := newTestAgent(&fakeRunner{result: wexec.Result{ExitCode: 0, Stdout: "linux box"}})
	a.Client = client

	didWork, restart := a.pollOnce(context.Background())
	if restart {
		t.Fatalf("did not expect restart")
	}
	if !didWork {
		t.Fatalf("expected pollOnce to report work done")
	}
	if submitted.Status != "succeeded" || submitted.Stdout != "linux box" {
		t.Fatalf("unexpected submitted result: %+v", submitted)
	}
}

func TestPollOnceNoTaskIsNoop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`null`))
	}))
	defer ts.Close()
	client, _ := hubclient.New(hubclient.Options{
		BaseURL: ts.URL, AllowInsecure: true, HTTPClient: ts.Client(),
	})
	a := newTestAgent(&fakeRunner{})
	a.Client = client
	didWork, restart := a.pollOnce(context.Background())
	if restart || didWork {
		t.Fatalf("idle poll should not report work or restart")
	}
}
