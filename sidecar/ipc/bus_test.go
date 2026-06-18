package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Bus construction
// ---------------------------------------------------------------------------

func TestNewBus(t *testing.T) {
	b := NewBus(strings.NewReader(""), &bytes.Buffer{})
	if b == nil {
		t.Fatal("NewBus returned nil")
	}
	if b.in == nil {
		t.Error("in reader not initialized")
	}
	if b.out == nil {
		t.Error("out writer not initialized")
	}
	if len(b.handlers) != 0 {
		t.Errorf("handlers = %d; want 0", len(b.handlers))
	}
	if cap(b.sem) != maxConcurrentRequests {
		t.Errorf("sem cap = %d; want %d", cap(b.sem), maxConcurrentRequests)
	}
	// No pending slots should be taken initially.
	if len(b.sem) != 0 {
		t.Errorf("sem len = %d; want 0", len(b.sem))
	}
}

func TestRegister(t *testing.T) {
	b := NewBus(strings.NewReader(""), &bytes.Buffer{})
	h := func(_ context.Context, _ json.RawMessage) (any, error) {
		return "ok", nil
	}
	b.Register("test", h)
	if len(b.handlers) != 1 {
		t.Errorf("handlers = %d; want 1", len(b.handlers))
	}
	if b.handlers["test"] == nil {
		t.Error("handler 'test' not registered")
	}
}

// ---------------------------------------------------------------------------
// Dispatch — success
// ---------------------------------------------------------------------------

func TestDispatchSuccess(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("ping", func(_ context.Context, _ json.RawMessage) (any, error) {
		return "pong", nil
	})

	// Manually call dispatch (Run is tested separately below).
	line := `{"jsonrpc":"2.0","method":"ping","params":{},"id":1}` + "\n"
	b.dispatch([]byte(line))

	// Read the response line from the buffer.
	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v; want 2.0", resp["jsonrpc"])
	}
	if resp["result"] != "pong" {
		t.Errorf("result = %v; want pong", resp["result"])
	}
	if resp["error"] != nil {
		t.Errorf("error = %v; want nil", resp["error"])
	}
	// ID must be a float64 (JSON numbers decode as float64)
	id, _ := resp["id"].(float64)
	if id != 1 {
		t.Errorf("id = %v; want 1", resp["id"])
	}
}

// ---------------------------------------------------------------------------
// Dispatch — unknown method
// ---------------------------------------------------------------------------

func TestDispatchUnknownMethod(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)

	line := `{"jsonrpc":"2.0","method":"nonexistent","id":2}` + "\n"
	b.dispatch([]byte(line))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] == nil {
		t.Fatal("expected error for unknown method")
	}
	errObj := resp["error"].(map[string]any)
	if !strings.Contains(errObj["message"].(string), "unknown method") {
		t.Errorf("error message = %v; want 'unknown method'", errObj["message"])
	}
}

// ---------------------------------------------------------------------------
// Dispatch — invalid JSON
// ---------------------------------------------------------------------------

func TestDispatchInvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)

	b.dispatch([]byte(`{invalid`))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] == nil {
		t.Fatal("expected error for invalid JSON")
	}
	errObj := resp["error"].(map[string]any)
	if !strings.Contains(errObj["message"].(string), "invalid JSON") {
		t.Errorf("error message = %v; want 'invalid JSON'", errObj["message"])
	}
}

// ---------------------------------------------------------------------------
// Dispatch — handler error
// ---------------------------------------------------------------------------

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestDispatchHandlerError(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("fail", func(_ context.Context, _ json.RawMessage) (any, error) {
		return nil, &testError{msg: "something went wrong"}
	})

	line := `{"jsonrpc":"2.0","method":"fail","id":3}` + "\n"
	b.dispatch([]byte(line))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] == nil {
		t.Fatal("expected error")
	}
	errObj := resp["error"].(map[string]any)
	if !strings.Contains(errObj["message"].(string), "something went wrong") {
		t.Errorf("error message = %v; want 'something went wrong'", errObj["message"])
	}
	if resp["result"] != nil {
		t.Errorf("result = %v; want nil", resp["result"])
	}
}

// ---------------------------------------------------------------------------
// Dispatch — handler panic recovery
// ---------------------------------------------------------------------------

func TestDispatchPanicRecovery(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("panic", func(_ context.Context, _ json.RawMessage) (any, error) {
		panic("oops")
	})

	line := `{"jsonrpc":"2.0","method":"panic","id":4}` + "\n"
	b.dispatch([]byte(line))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] == nil {
		t.Fatal("expected error after panic recovery")
	}
	errObj := resp["error"].(map[string]any)
	if !strings.Contains(errObj["message"].(string), "handler panic") {
		t.Errorf("error message = %v; want 'handler panic'", errObj["message"])
	}
}

// ---------------------------------------------------------------------------
// Run — reads and dispatches from stdin
// ---------------------------------------------------------------------------

func TestRunDispatch(t *testing.T) {
	var inBuf bytes.Buffer
	var outBuf bytes.Buffer
	b := NewBus(&inBuf, &outBuf)
	b.Register("echo", func(_ context.Context, params json.RawMessage) (any, error) {
		return string(params), nil
	})

	// Write two requests into the input buffer.
	inBuf.WriteString(`{"jsonrpc":"2.0","method":"echo","params":"hello","id":10}` + "\n")
	inBuf.WriteString(`{"jsonrpc":"2.0","method":"echo","params":"world","id":20}` + "\n")

	// Run in background — it will read until EOF.
	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Run()
	}()

	// Wait for Run to finish (it exits on EOF after processing both lines).
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run timed out")
	}

	// Give dispatched goroutines a moment to write their responses.
	time.Sleep(50 * time.Millisecond)

	// Verify both responses came back.
	scanner := bufio.NewScanner(&outBuf)
	lines := 0
	for scanner.Scan() {
		lines++
	}
	if lines != 2 {
		t.Errorf("got %d response lines; want 2", lines)
	}
}

// ---------------------------------------------------------------------------
// Run — EOF on input exits cleanly
// ---------------------------------------------------------------------------

func TestRunEOF(t *testing.T) {
	b := NewBus(strings.NewReader(""), &bytes.Buffer{})
	err := b.Run()
	if err != nil {
		t.Fatalf("Run on empty input returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Run — Close cancels the bus while reading
// ---------------------------------------------------------------------------

func TestRunCloseCancels(t *testing.T) {
	// Use an unbuffered pipe so the bus blocks waiting for input.
	pr, pw := io.Pipe()

	var outBuf bytes.Buffer
	b := NewBus(pr, &outBuf)
	b.Register("test", func(_ context.Context, _ json.RawMessage) (any, error) {
		return "ok", nil
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Run()
	}()

	// Let the bus start reading, then close it.
	time.Sleep(50 * time.Millisecond)
	b.Close()
	pw.Close() // unblock the pipe reader so Run() can check ctx.Done()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after Close")
	}
}

// ---------------------------------------------------------------------------
// Notify — sends unsolicited notification
// ---------------------------------------------------------------------------

func TestNotify(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)

	err := b.Notify("state_changed", map[string]string{"state": "RUNNING"})
	if err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	var notif map[string]any
	if err := json.NewDecoder(&buf).Decode(&notif); err != nil {
		t.Fatalf("failed to decode notification: %v", err)
	}
	if notif["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v; want 2.0", notif["jsonrpc"])
	}
	if notif["method"] != "state_changed" {
		t.Errorf("method = %v; want state_changed", notif["method"])
	}
	if notif["id"] != nil {
		t.Errorf("id = %v; want nil (notification has no id)", notif["id"])
	}
}

// ---------------------------------------------------------------------------
// Done — returns a channel that closes on Close
// ---------------------------------------------------------------------------

func TestDoneClosedOnClose(t *testing.T) {
	b := NewBus(strings.NewReader(""), &bytes.Buffer{})

	select {
	case <-b.Done():
		t.Fatal("Done channel closed before Close")
	default:
	}

	b.Close()

	select {
	case <-b.Done():
		// expected
	default:
		t.Fatal("Done channel still open after Close")
	}
}

// ---------------------------------------------------------------------------
// Concurrency — semaphore bounds concurrent handlers
// ---------------------------------------------------------------------------

func TestSemaphoreBoundsConcurrency(t *testing.T) {
	var inBuf bytes.Buffer
	var outBuf bytes.Buffer
	b := NewBus(&inBuf, &outBuf)

	var active int32
	b.Register("block", func(_ context.Context, _ json.RawMessage) (any, error) {
		atomic.AddInt32(&active, 1)
		// Block until context is done.
		<-b.ctx.Done()
		atomic.AddInt32(&active, -1)
		return nil, nil
	})

	// Fire 120 requests (20 above the semaphore limit of 100).
	for i := 0; i < 120; i++ {
		inBuf.WriteString(`{"jsonrpc":"2.0","method":"block","id":`)
		inBuf.WriteString(string(rune('0' + i%10))) // simple ascii digit for id
		inBuf.WriteString(`}` + "\n")
	}

	errCh := make(chan error, 1)
	go func() { errCh <- b.Run() }()
	time.Sleep(200 * time.Millisecond) // let goroutines spin up

	// Verify active <= 100 (crude check — there's a race window).
	if n := atomic.LoadInt32(&active); n > 100 {
		t.Errorf("active = %d; wanted max 100 (semaphore not respected)", n)
	}

	b.Close()
	<-errCh
}

// ---------------------------------------------------------------------------
// Handlers receive bus context (alive before close)
// ---------------------------------------------------------------------------

func TestHandlerContextAlive(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("check-ctx", func(ctx context.Context, _ json.RawMessage) (any, error) {
		select {
		case <-ctx.Done():
			return "cancelled", ctx.Err()
		default:
			return "alive", nil
		}
	})

	line := `{"jsonrpc":"2.0","method":"check-ctx","id":1}` + "\n"
	b.dispatch([]byte(line))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["result"] != "alive" {
		t.Errorf("result = %v; want 'alive'", resp["result"])
	}
}

// ---------------------------------------------------------------------------
// Run with close cancels — verifies Close causes Run to exit
// ---------------------------------------------------------------------------

func TestRunExitsOnCloseNoInput(t *testing.T) {
	pr, pw := io.Pipe()
	b := NewBus(pr, &bytes.Buffer{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Run()
	}()

	time.Sleep(50 * time.Millisecond)
	b.Close()
	// Close the write side so the read side unblocks too.
	pw.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit after Close + pipe close")
	}
}

// ---------------------------------------------------------------------------
// Multiple handlers can be registered and dispatched
// ---------------------------------------------------------------------------

func TestMultipleHandlers(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("a", func(_ context.Context, _ json.RawMessage) (any, error) {
		return "a-result", nil
	})
	b.Register("b", func(_ context.Context, _ json.RawMessage) (any, error) {
		return "b-result", nil
	})

	b.dispatch([]byte(`{"jsonrpc":"2.0","method":"a","id":1}` + "\n"))
	b.dispatch([]byte(`{"jsonrpc":"2.0","method":"b","id":2}` + "\n"))

	var results []string
	dec := json.NewDecoder(&buf)
	for dec.More() {
		var resp map[string]any
		if err := dec.Decode(&resp); err != nil {
			break
		}
		results = append(results, resp["result"].(string))
	}
	if len(results) != 2 {
		t.Fatalf("got %d responses; want 2", len(results))
	}
	if results[0] != "a-result" && results[1] != "a-result" {
		t.Errorf("missing a-result: %v", results)
	}
	if results[0] != "b-result" && results[1] != "b-result" {
		t.Errorf("missing b-result: %v", results)
	}
}

// ---------------------------------------------------------------------------
// Dispatch — handler uses cancelled context
// ---------------------------------------------------------------------------

func TestDispatchContextCancelled(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("slow", func(ctx context.Context, _ json.RawMessage) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	// Close the bus to cancel the context first.
	b.Close()

	line := `{"jsonrpc":"2.0","method":"slow","id":5}` + "\n"
	b.dispatch([]byte(line))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] == nil {
		t.Fatal("expected error when context is cancelled")
	}
	errObj := resp["error"].(map[string]any)
	if !strings.Contains(errObj["message"].(string), "bus closed") {
		t.Errorf("error message = %v; want 'bus closed'", errObj["message"])
	}
}

// ---------------------------------------------------------------------------
// Dispatch — panic recovery with nil ID (edge case)
// ---------------------------------------------------------------------------

func TestDispatchPanicNoID(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("panic", func(_ context.Context, _ json.RawMessage) (any, error) {
		panic("boom")
	})

	// Notification-style requests have no ID — panic should still be recovered.
	line := `{"jsonrpc":"2.0","method":"panic"}` + "\n"
	b.dispatch([]byte(line))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] == nil {
		t.Fatal("expected error after panic")
	}
}

// ---------------------------------------------------------------------------
// Register — overwriting handler
// ---------------------------------------------------------------------------

func TestRegisterOverwrite(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)
	b.Register("dup", func(_ context.Context, _ json.RawMessage) (any, error) {
		return "first", nil
	})
	b.Register("dup", func(_ context.Context, _ json.RawMessage) (any, error) {
		return "second", nil
	})

	b.dispatch([]byte(`{"jsonrpc":"2.0","method":"dup","id":1}` + "\n"))

	var resp map[string]any
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["result"] != "second" {
		t.Errorf("result = %v; want 'second'", resp["result"])
	}
}

// ---------------------------------------------------------------------------
// Notify — multiple notifications in sequence
// ---------------------------------------------------------------------------

func TestNotifyMultiple(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus(strings.NewReader(""), &buf)

	for i := 0; i < 5; i++ {
		if err := b.Notify("evt", i); err != nil {
			t.Fatalf("Notify %d: %v", i, err)
		}
	}

	// Count lines in output.
	lines := strings.Count(buf.String(), "\n")
	if lines != 5 {
		t.Errorf("got %d notification lines; want 5", lines)
	}
}

// ---------------------------------------------------------------------------
// Close — idempotent
// ---------------------------------------------------------------------------

func TestCloseIdempotent(t *testing.T) {
	b := NewBus(strings.NewReader(""), &bytes.Buffer{})
	b.Close()
	b.Close() // second call should not panic
	b.Close() // third call should not panic
}

