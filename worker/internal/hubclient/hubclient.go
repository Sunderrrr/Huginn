// Package hubclient is the worker's typed HTTP client for the hub API. It uses
// the per-worker credentials on every authenticated call and refuses plaintext
// transport unless explicitly allowed (dev only).
package hubclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to the hub.
type Client struct {
	baseURL       string
	workerID      string
	workerSecret  string
	http          *http.Client
	allowInsecure bool
}

// Options configures a Client.
type Options struct {
	BaseURL       string
	WorkerID      string
	WorkerSecret  string
	AllowInsecure bool
	HTTPClient    *http.Client
}

// New constructs a Client, validating the transport policy.
func New(opts Options) (*Client, error) {
	base := strings.TrimRight(opts.BaseURL, "/")
	if !opts.AllowInsecure && !strings.HasPrefix(base, "https://") {
		return nil, fmt.Errorf("hub URL must use https (got %q); set allow_insecure for dev", base)
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 70 * time.Second}
	}
	return &Client{
		baseURL:       base,
		workerID:      opts.WorkerID,
		workerSecret:  opts.WorkerSecret,
		http:          hc,
		allowInsecure: opts.AllowInsecure,
	}, nil
}

// --- Wire types (mirror the hub schemas) ---

type EnrollRequest struct {
	Token         string         `json:"token"`
	Name          string         `json:"name"`
	Hostname      string         `json:"hostname,omitempty"`
	IPAddress     string         `json:"ip_address,omitempty"`
	Arch          string         `json:"arch"`
	OSInfo        map[string]any `json:"os_info,omitempty"`
	WorkerVersion string         `json:"worker_version,omitempty"`
}

type EnrollResponse struct {
	WorkerID     string `json:"worker_id"`
	WorkerSecret string `json:"worker_secret"`
	State        string `json:"state"`
}

type HeartbeatRequest struct {
	WorkerVersion string `json:"worker_version,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`
}

type HeartbeatResponse struct {
	TargetWorkerVersion    string   `json:"target_worker_version"`
	ExecMode               string   `json:"exec_mode"`
	AllowedReleaseDomains  []string `json:"allowed_release_domains"`
}

// Task is a unit of work handed to the worker.
type Task struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	ActionName string         `json:"action_name"`
	Payload    map[string]any `json:"payload"`
}

// TaskResult is submitted back to the hub.
type TaskResult struct {
	Status   string `json:"status"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Enroll registers this machine with the hub using an enrollment token.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/worker/enroll", req, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat reports liveness/version and returns the desired target version.
func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.do(ctx, http.MethodPost, "/api/worker/heartbeat", req, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// PollNextTask returns the next queued task, or nil when the queue is empty.
func (c *Client) PollNextTask(ctx context.Context) (*Task, error) {
	var task *Task
	if err := c.do(ctx, http.MethodGet, "/api/worker/tasks/next", nil, &task, true); err != nil {
		return nil, err
	}
	return task, nil
}

// SubmitResult posts the outcome of a task.
func (c *Client) SubmitResult(ctx context.Context, taskID string, res TaskResult) error {
	path := fmt.Sprintf("/api/worker/tasks/%s/result", taskID)
	return c.do(ctx, http.MethodPost, path, res, nil, true)
}

func (c *Client) do(
	ctx context.Context, method, path string, body, out any, auth bool,
) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("X-Worker-Id", c.workerID)
		req.Header.Set("X-Worker-Secret", c.workerSecret)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// APIError carries a non-2xx response from the hub.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("hub returned %d: %s", e.StatusCode, e.Body)
}
