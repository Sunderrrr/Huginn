package hubclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRejectsPlaintextByDefault(t *testing.T) {
	if _, err := New(Options{BaseURL: "http://hub.local"}); err == nil {
		t.Fatalf("expected rejection of http:// without AllowInsecure")
	}
}

func TestNewAllowsPlaintextWhenOptedIn(t *testing.T) {
	if _, err := New(Options{BaseURL: "http://hub.local", AllowInsecure: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHeartbeatSendsAuthHeaders(t *testing.T) {
	var gotID, gotSecret string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get("X-Worker-Id")
		gotSecret = r.Header.Get("X-Worker-Secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"target_worker_version":"v1.0.0","exec_mode":"whitelist"}`))
	}))
	defer ts.Close()

	c, err := New(Options{
		BaseURL: ts.URL, WorkerID: "vm-1", WorkerSecret: "sekret",
		AllowInsecure: true, HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Heartbeat(context.Background(), HeartbeatRequest{WorkerVersion: "v0.9"})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if gotID != "vm-1" || gotSecret != "sekret" {
		t.Fatalf("missing/incorrect auth headers: id=%q secret=%q", gotID, gotSecret)
	}
	if resp.TargetWorkerVersion != "v1.0.0" {
		t.Fatalf("unexpected target version %q", resp.TargetWorkerVersion)
	}
}

func TestPollNextTaskNullMeansNoWork(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`null`))
	}))
	defer ts.Close()
	c, _ := New(Options{BaseURL: ts.URL, AllowInsecure: true, HTTPClient: ts.Client()})
	task, err := c.PollNextTask(context.Background(), 0)
	if err != nil {
		t.Fatalf("PollNextTask: %v", err)
	}
	if task != nil {
		t.Fatalf("expected nil task, got %+v", task)
	}
}

func TestPollNextTaskReturnsTask(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"t1","type":"action","action_name":"status","payload":{}}`))
	}))
	defer ts.Close()
	c, _ := New(Options{BaseURL: ts.URL, AllowInsecure: true, HTTPClient: ts.Client()})
	task, err := c.PollNextTask(context.Background(), 0)
	if err != nil {
		t.Fatalf("PollNextTask: %v", err)
	}
	if task == nil || task.ID != "t1" || task.Type != "action" {
		t.Fatalf("unexpected task: %+v", task)
	}
}

func TestNon2xxReturnsAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"nope"}`))
	}))
	defer ts.Close()
	c, _ := New(Options{BaseURL: ts.URL, AllowInsecure: true, HTTPClient: ts.Client()})
	_, err := c.Heartbeat(context.Background(), HeartbeatRequest{})
	if err == nil {
		t.Fatalf("expected APIError")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 APIError, got %v", err)
	}
}
