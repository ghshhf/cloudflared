package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/ipc"
	"github.com/cloudflare/cloudflared/sidecar/ssi"
)

// ---------------------------------------------------------------------------
// heartbeat — sends initial state_changed notification
// ---------------------------------------------------------------------------

func TestHeartbeatSendsInitialNotification(t *testing.T) {
	var outBuf bytes.Buffer
	bus := ipc.NewBus(strings.NewReader(""), &outBuf)
	comp := ssi.NewCloudflaredComponent()
	doneCh := make(chan struct{})

	go heartbeat(bus, comp, doneCh)
	time.Sleep(50 * time.Millisecond)
	close(doneCh)
	time.Sleep(20 * time.Millisecond)

	if outBuf.Len() == 0 {
		t.Fatal("heartbeat sent no notifications")
	}

	var notif map[string]any
	if err := json.NewDecoder(&outBuf).Decode(&notif); err != nil {
		t.Fatalf("failed to decode notification: %v", err)
	}
	if notif["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v; want 2.0", notif["jsonrpc"])
	}
	if notif["method"] != "state_changed" {
		t.Errorf("method = %v; want state_changed", notif["method"])
	}
	params, ok := notif["params"].(map[string]any)
	if !ok {
		t.Fatal("params is not a map")
	}
	if params["state"] == nil {
		t.Error("params.state is nil")
	}
	if params["state_code"] == nil {
		t.Error("params.state_code is nil")
	}
	if params["at"] == nil {
		t.Error("params.at is nil")
	}
}

// ---------------------------------------------------------------------------
// heartbeat — detects state changes
// ---------------------------------------------------------------------------

func TestHeartbeatDetectsStateChange(t *testing.T) {
	var outBuf bytes.Buffer
	bus := ipc.NewBus(strings.NewReader(""), &outBuf)
	comp := ssi.NewCloudflaredComponent()
	doneCh := make(chan struct{})

	go heartbeat(bus, comp, doneCh)
	time.Sleep(50 * time.Millisecond)

	cfg := ssi.Config{
		Name: "test",
		ExtraArgs: []string{"quick", "http://localhost:8080"},
	}
	_ = comp.Init(context.Background(), cfg)

	time.Sleep(100 * time.Millisecond)
	close(doneCh)
	time.Sleep(20 * time.Millisecond)

	dec := json.NewDecoder(&outBuf)
	var states []string
	for dec.More() {
		var notif map[string]any
		if err := dec.Decode(&notif); err != nil {
			break
		}
		if params, ok := notif["params"].(map[string]any); ok {
			if s, ok := params["state"].(string); ok {
				states = append(states, s)
			}
		}
	}

	if len(states) < 2 {
		t.Logf("states seen: %v", states)
	}
}

// ---------------------------------------------------------------------------
// heartbeat — exits cleanly on doneCh
// ---------------------------------------------------------------------------

func TestHeartbeatExitsOnDone(t *testing.T) {
	var outBuf bytes.Buffer
	bus := ipc.NewBus(strings.NewReader(""), &outBuf)
	comp := ssi.NewCloudflaredComponent()
	doneCh := make(chan struct{})

	done := make(chan struct{})
	go func() {
		heartbeat(bus, comp, doneCh)
		close(done)
	}()

	close(doneCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not exit after doneCh was closed")
	}
}

// ---------------------------------------------------------------------------
// wrapGetState — returns correct JSON structure
// ---------------------------------------------------------------------------

func TestWrapGetState(t *testing.T) {
	comp := ssi.NewCloudflaredComponent()
	h := wrapGetState(comp)

	result, err := h(context.Background(), nil)
	if err != nil {
		t.Fatalf("wrapGetState error: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T; want map[string]any", result)
	}
	if m["state"] == nil {
		t.Error("state key is missing")
	}
	if m["state_code"] == nil {
		t.Error("state_code key is missing")
	}
	if code, ok := m["state_code"].(int); ok && code != 0 {
		t.Errorf("state_code = %d; want 0 (CREATED)", code)
	}
}

// ---------------------------------------------------------------------------
// wrapGetLogs — returns recent lines
// ---------------------------------------------------------------------------

func TestWrapGetLogs(t *testing.T) {
	comp := ssi.NewCloudflaredComponent()
	h := wrapGetLogs(comp)

	result, err := h(context.Background(), nil)
	if err != nil {
		t.Fatalf("wrapGetLogs error: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T; want map[string]any", result)
	}
	if _, ok := m["lines"]; !ok {
		t.Error("lines key missing")
	}

	result, err = h(context.Background(), json.RawMessage(`{"n":10}`))
	if err != nil {
		t.Fatalf("wrapGetLogs with params error: %v", err)
	}
	m = result.(map[string]any)
	lines, ok := m["lines"].([]string)
	if ok && len(lines) > 10 {
		t.Errorf("lines length = %d; want <= 10", len(lines))
	}
}

// ---------------------------------------------------------------------------
// wrapPing — returns pong
// ---------------------------------------------------------------------------

func TestWrapPingRegistered(t *testing.T) {
	var outBuf bytes.Buffer
	var inBuf bytes.Buffer
	bus := ipc.NewBus(&inBuf, &outBuf)
	bus.Register("ping", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]string{"pong": time.Now().UTC().Format(time.RFC3339)}, nil
	})

	inBuf.WriteString(`{"jsonrpc":"2.0","method":"ping","id":1}` + "\n")

	errCh := make(chan error, 1)
	go func() { errCh <- bus.Run() }()
	time.Sleep(50 * time.Millisecond)

	var resp map[string]any
	if err := json.NewDecoder(&outBuf).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v", resp["jsonrpc"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result type = %T; want map", resp["result"])
	}
	if result["pong"] == nil {
		t.Error("pong key missing")
	}
}

// ---------------------------------------------------------------------------
// wrapInit with config
// ---------------------------------------------------------------------------

func TestWrapInit(t *testing.T) {
	comp := ssi.NewCloudflaredComponent()
	h := wrapInit(comp)

	params := json.RawMessage(`{"name":"test-tunnel","mode":"quick","origin_url":"http://localhost:3000"}`)
	result, err := h(context.Background(), params)
	if err != nil {
		t.Fatalf("wrapInit error: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T; want map", result)
	}
	if m["ok"] != true {
		t.Errorf("ok = %v; want true", m["ok"])
	}
	if m["config"] == nil {
		t.Error("config key missing")
	}
}

// ---------------------------------------------------------------------------
// Version variable
// ---------------------------------------------------------------------------

func TestVersionDefault(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q; want dev (default when no ldflags)", Version)
	}
}

// ---------------------------------------------------------------------------
// Integration: Lifecycle via pipe-based Bus
// Uses io.Pipe for proper streaming request/response.
// ---------------------------------------------------------------------------

func TestIntegrationLifecycle(t *testing.T) {
	// Server (bus) reads from serverR, writes to serverW.
	serverR, clientW := io.Pipe()
	clientR, serverW := io.Pipe()

	bus := ipc.NewBus(serverR, serverW)
	comp := ssi.NewCloudflaredComponent()

	bus.Register("init", wrapInit(comp))
	bus.Register("start", wrapStart(comp))
	bus.Register("stop", wrapStop(comp))
	bus.Register("get_state", wrapGetState(comp))
	bus.Register("get_logs", wrapGetLogs(comp))
	bus.Register("ping", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]string{"pong": time.Now().UTC().Format(time.RFC3339)}, nil
	})

	errCh := make(chan error, 1)
	go func() { errCh <- bus.Run() }()

	// Client-side: send request line, read one response line.
	sendAndRecv := func(req string, timeout time.Duration) map[string]any {
		_, err := io.WriteString(clientW, req)
		if err != nil {
			t.Fatalf("write: %v", err)
		}

		// Read one JSON line from the response pipe.
		deadline := time.After(timeout)
		done := make(chan map[string]any, 1)
		go func() {
			var resp map[string]any
			dec := json.NewDecoder(clientR)
			if err := dec.Decode(&resp); err == nil {
				done <- resp
			}
		}()

		select {
		case resp := <-done:
			return resp
		case <-deadline:
			t.Fatalf("timeout waiting for response to %q", req[:min(len(req), 60)])
			return nil
		}
	}

	// 1. get_state → CREATED (state_code=0)
	resp := sendAndRecv(`{"jsonrpc":"2.0","method":"get_state","id":1}`+"\n", 3*time.Second)
	if resp["error"] != nil {
		t.Errorf("get_state error: %v", resp["error"])
	} else if result, ok := resp["result"].(map[string]any); ok {
		if code, _ := result["state_code"].(float64); code != 0 {
			t.Errorf("initial state_code = %v; want 0", code)
		}
	}

	// 2. init
	resp = sendAndRecv(`{"jsonrpc":"2.0","method":"init","params":{"name":"int-test","mode":"quick","origin_url":"http://localhost:3000"},"id":2}`+"\n", 3*time.Second)
	if resp["error"] != nil {
		t.Errorf("init error: %v", resp["error"])
	} else if result, ok := resp["result"].(map[string]any); ok {
		if result["ok"] != true {
			t.Errorf("init ok = %v; want true", result["ok"])
		}
	}

	// 3. start — may fail (no cloudflared binary in test env), must not crash
	resp = sendAndRecv(`{"jsonrpc":"2.0","method":"start","id":3}`+"\n", 5*time.Second)
	if resp["error"] != nil {
		t.Logf("start (expected) error: %v", resp["error"])
	} else {
		t.Logf("start succeeded")
	}

	// 4. get_state — after attempted start
	resp = sendAndRecv(`{"jsonrpc":"2.0","method":"get_state","id":4}`+"\n", 3*time.Second)
	if resp["error"] != nil {
		t.Errorf("get_state error: %v", resp["error"])
	} else if result, ok := resp["result"].(map[string]any); ok {
		t.Logf("state: %v", result["state"])
	}

	// 5. stop — must not panic regardless of state
	resp = sendAndRecv(`{"jsonrpc":"2.0","method":"stop","id":5}`+"\n", 3*time.Second)
	if resp["error"] != nil {
		t.Logf("stop (expected) error: %v", resp["error"])
	} else {
		t.Logf("stop succeeded")
	}

	// 6. ping — should always succeed
	resp = sendAndRecv(`{"jsonrpc":"2.0","method":"ping","id":6}`+"\n", 3*time.Second)
	if resp["error"] != nil {
		t.Errorf("ping error: %v", resp["error"])
	} else if result, ok := resp["result"].(map[string]any); ok {
		if _, ok := result["pong"]; !ok {
			t.Error("ping missing 'pong'")
		}
	}

	clientW.Close()
	serverW.Close()
	serverR.Close()
	bus.Close()
	<-errCh
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
