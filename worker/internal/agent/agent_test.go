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

	"github.com/Internal-website/Huginn/worker/internal/config"
	wexec "github.com/Internal-website/Huginn/worker/internal/exec"
	"github.com/Internal-website/Huginn/worker/internal/hubclient"
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
		Runner: runner,
		State:  &config.State{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
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

func TestDispatchCommandUsesShell(t *testing.T) {
	// Free-command mode (hub-gated unrestricted) intentionally goes through a shell.
	runner := &fakeRunner{result: wexec.Result{ExitCode: 0}}
	a := newTestAgent(runner)
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

	if restart := a.pollOnce(context.Background()); restart {
		t.Fatalf("did not expect restart")
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
	if restart := a.pollOnce(context.Background()); restart {
		t.Fatalf("idle poll should not request restart")
	}
}
