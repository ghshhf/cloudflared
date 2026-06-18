package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- mock component ----

type mockComponent struct {
	name        string
	state       string
	backendType string
	backendName string
	lines       []string
}

func (m *mockComponent) Name() string        { return m.name }
func (m *mockComponent) State() string       { return m.state }
func (m *mockComponent) BackendType() string { return m.backendType }
func (m *mockComponent) BackendName() string { return m.backendName }
func (m *mockComponent) RecentLines(n int) []string {
	if n > len(m.lines) {
		n = len(m.lines)
	}
	return m.lines[:n]
}

// ---- mock controller ----

type mockController struct {
	state    string
	startErr error
	stopErr  error
	started  bool
	stopped  bool
}

func (m *mockController) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.started = true
	m.state = "RUNNING"
	return nil
}

func (m *mockController) Stop(ctx context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.stopped = true
	m.state = "STOPPED"
	return nil
}

func (m *mockController) State() string { return m.state }

// ---- render the dashboard to check the template ----

func testServer(t *testing.T, comp Component, ctrl Controller) *httptest.Server {
	t.Helper()
	s := NewServer(":0", comp)
	if ctrl != nil {
		s.SetController(ctrl)
	}
	// Start the server in background; we'll manually test via a test server.
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/api/status", s.statusHandler)
	mux.HandleFunc("/api/start", s.startHandler)
	mux.HandleFunc("/api/stop", s.stopHandler)
	mux.HandleFunc("/api/logs", s.logsHandler)
	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// Dashboard — index
// ---------------------------------------------------------------------------

func TestIndexHandler(t *testing.T) {
	comp := &mockComponent{
		name:        "my-tunnel",
		state:       "RUNNING",
		backendType: "cloudflare",
		backendName: "cloudflare://default",
		lines:       []string{"line1", "line2"},
	}
	ts := testServer(t, comp, nil)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}

	// Check template renders key fields.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, "my-tunnel") {
		t.Error("page missing component name")
	}
	if !strings.Contains(html, "RUNNING") {
		t.Error("page missing state")
	}
	if !strings.Contains(html, "line1") || !strings.Contains(html, "line2") {
		t.Error("page missing log lines")
	}
}

// ---------------------------------------------------------------------------
// /api/status
// ---------------------------------------------------------------------------

func TestStatusHandler(t *testing.T) {
	comp := &mockComponent{
		name:        "status-test",
		state:       "RUNNING",
		backendType: "wireguard",
		backendName: "wg0",
	}
	ts := testServer(t, comp, nil)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data["name"] != "status-test" {
		t.Errorf("name = %v; want status-test", data["name"])
	}
	if data["state"] != "RUNNING" {
		t.Errorf("state = %v; want RUNNING", data["state"])
	}
}

// ---------------------------------------------------------------------------
// /api/logs
// ---------------------------------------------------------------------------

func TestLogsHandler(t *testing.T) {
	comp := &mockComponent{
		lines: []string{"log entry 1", "log entry 2"},
	}
	ts := testServer(t, comp, nil)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/logs")
	if err != nil {
		t.Fatalf("GET /api/logs: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	lines := data["lines"].([]any)
	if len(lines) != 2 {
		t.Errorf("len(lines) = %d; want 2", len(lines))
	}
}

// ---------------------------------------------------------------------------
// /api/start — success
// ---------------------------------------------------------------------------

func TestStartHandlerSuccess(t *testing.T) {
	ctrl := &mockController{state: "STOPPED"}
	ts := testServer(t, &mockComponent{}, ctrl)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/start", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/start: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data["status"] != "ok" {
		t.Errorf("status = %q; want ok", data["status"])
	}
	if data["state"] != "RUNNING" {
		t.Errorf("state = %q; want RUNNING", data["state"])
	}
	if !ctrl.started {
		t.Error("controller.Start was not called")
	}
}

// ---------------------------------------------------------------------------
// /api/start — no controller
// ---------------------------------------------------------------------------

func TestStartHandlerNoController(t *testing.T) {
	ts := testServer(t, &mockComponent{}, nil)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/start", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/start: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d; want 501", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// /api/start — error
// ---------------------------------------------------------------------------

func TestStartHandlerError(t *testing.T) {
	ctrl := &mockController{startErr: errors.New("connection refused")}
	ts := testServer(t, &mockComponent{}, ctrl)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/start", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/start: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// /api/start — method not allowed
// ---------------------------------------------------------------------------

func TestStartHandlerMethodNotAllowed(t *testing.T) {
	ts := testServer(t, &mockComponent{}, nil)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/start")
	if err != nil {
		t.Fatalf("GET /api/start: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// /api/stop — success
// ---------------------------------------------------------------------------

func TestStopHandlerSuccess(t *testing.T) {
	ctrl := &mockController{state: "RUNNING"}
	ts := testServer(t, &mockComponent{}, ctrl)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/stop", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/stop: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data["status"] != "ok" {
		t.Errorf("status = %q; want ok", data["status"])
	}
	if data["state"] != "STOPPED" {
		t.Errorf("state = %q; want STOPPED", data["state"])
	}
	if !ctrl.stopped {
		t.Error("controller.Stop was not called")
	}
}

// ---------------------------------------------------------------------------
// /api/stop — no controller
// ---------------------------------------------------------------------------

func TestStopHandlerNoController(t *testing.T) {
	ts := testServer(t, &mockComponent{}, nil)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/stop", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/stop: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d; want 501", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// /api/stop — error
// ---------------------------------------------------------------------------

func TestStopHandlerError(t *testing.T) {
	ctrl := &mockController{stopErr: errors.New("already stopping")}
	ts := testServer(t, &mockComponent{}, ctrl)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/stop", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/stop: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// NewServer and helpers
// ---------------------------------------------------------------------------

func TestNewServer(t *testing.T) {
	s := NewServer(":8080", &mockComponent{})
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if !s.IsEnabled() {
		t.Error(":8080 should be enabled")
	}
}

func TestServerDisabled(t *testing.T) {
	s := NewServer("", &mockComponent{})
	if s.IsEnabled() {
		t.Error("empty address should be disabled")
	}
	s = NewServer("off", &mockComponent{})
	if s.IsEnabled() {
		t.Error("\"off\" should be disabled")
	}
}

func TestSetVersion(t *testing.T) {
	s := NewServer(":0", &mockComponent{})
	s.SetVersion("1.2.3")
	if s.version != "1.2.3" {
		t.Errorf("version = %q; want 1.2.3", s.version)
	}
}

func TestSetAuthToken(t *testing.T) {
	comp := &mockComponent{name: "auth-test"}
	s := NewServer(":0", comp)
	s.SetAuthToken("secret123")
	s.SetController(&mockController{state: "RUNNING"})

	// Mock the server.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/start", s.requireAuth(s.startHandler))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Without token.
	resp, err := http.Post(ts.URL+"/api/start", "application/json", nil)
	if err != nil {
		t.Fatalf("request without token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("without token: status = %d; want 401", resp.StatusCode)
	}

	// With valid token.
	req, _ := http.NewRequest("POST", ts.URL+"/api/start", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request with token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("with token: status = %d; want 200", resp.StatusCode)
	}

	// With wrong token.
	req, _ = http.NewRequest("POST", ts.URL+"/api/start", nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request with wrong token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("with wrong token: status = %d; want 401", resp.StatusCode)
	}
}

// ---- end ----
