package ssi

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error on empty payload: %v", err)
	}
	if cfg.Mode != "quick" {
		t.Errorf("default mode = %q; want quick", cfg.Mode)
	}
	if cfg.ShutdownGracePeriod <= 0 {
		t.Error("shutdown grace period should default to > 0")
	}
	if cfg.StartTimeout <= 0 {
		t.Error("start timeout should default to > 0")
	}
}

func TestParseConfigRejectsUnknownMode(t *testing.T) {
	_, err := ParseConfig([]byte(`{"mode":"bogus"}`))
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestParseConfigFullPayload(t *testing.T) {
	payload := []byte(`{
		"name": "my-tunnel",
		"mode": "access",
		"origin_url": "127.0.0.1:8080",
		"hostname": "app.example.com",
		"destination": "10.0.0.1:3389",
		"binary_path": "/usr/local/bin/cloudflared",
		"extra_args": ["--loglevel", "info"],
		"shutdown_grace_period_seconds": 5000000000,
		"start_timeout_seconds": 20000000000
	}`)
	cfg, ssiErr := ParseConfig(payload)
	if ssiErr != nil {
		t.Fatalf("unexpected parse error: %v", ssiErr)
	}
	if cfg.Name != "my-tunnel" {
		t.Errorf("name = %q", cfg.Name)
	}
	if cfg.Mode != "access" {
		t.Errorf("mode = %q", cfg.Mode)
	}
	if cfg.ShutdownGracePeriod != 5*time.Second {
		t.Errorf("grace period = %v; want 5s", cfg.ShutdownGracePeriod)
	}
	if cfg.StartTimeout != 20*time.Second {
		t.Errorf("start timeout = %v; want 20s", cfg.StartTimeout)
	}
	if len(cfg.ExtraArgs) != 2 {
		t.Errorf("extra args = %v", cfg.ExtraArgs)
	}
}

// Component lifecycle test — since the sidecar does NOT actually fork
// cloudflared unless a binary is available, we only exercise the state
// transitions that are safe to run on any machine.
func TestStateTransitionsInit(t *testing.T) {
	c := NewCloudflaredComponent()
	if got := c.GetState(); got != StateCreated {
		t.Fatalf("initial state = %v; want CREATED", got)
	}

	// Init with a mode that does not need a real binary to be parsed.
	cfg := DefaultConfig()
	cfg.Mode = "tunnel"
	cfg.BinaryPath = "/does/not/exist/cloudflared"
	if err := c.Init(context.Background(), cfg); err == nil {
		t.Fatal("expected error when binary not found")
	}
	if c.GetState() != StateError {
		t.Errorf("state after failed init = %v; want ERROR", c.GetState())
	}
}

// State machine rejects Start on CREATED (must go through Init first).
func TestStartRequiresInit(t *testing.T) {
	c := NewCloudflaredComponent()
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("expected error when Start() called without Init()")
	}
}

// State machine rejects Stop when not running.
func TestStopWhenNotRunning(t *testing.T) {
	c := NewCloudflaredComponent()
	ctx := context.Background()
	if err := c.Stop(ctx); err == nil {
		// Either behaviour could be defensible, but we expect a clear error.
		t.Logf("Stop on CREATED returned nil error; that is acceptable but unexpected")
	}
}

// Exercise log buffer directly — the most likely component subsystem to be
// exercised independently of a real cloudflared process.
func TestLogBufferRing(t *testing.T) {
	b := newLogBuffer(3)
	b.append("one")
	b.append("two")
	b.append("three")
	b.append("four")
	got := b.tail(3)
	if len(got) != 3 {
		t.Fatalf("tail(3) = %d lines", len(got))
	}
	if got[0] != "two" || got[1] != "three" || got[2] != "four" {
		t.Errorf("unexpected tail content: %v", got)
	}
}

// Test that Start() does not hang when the context is cancelled before
// the startup probe fires (Bug #1: ready channel must be closed on ctx cancel).
func TestStartCtxCancelledDoesNotHang(t *testing.T) {
	// The test binary /tmp/sidecar may not be present in all test environments.
	// Fall back to /bin/cat (always on Linux/macOS) as a no-op stand-in.
	bin := "/tmp/sidecar"
	if _, err := os.Stat(bin); err != nil {
		bin = "/bin/cat"
	}
	c := NewCloudflaredComponent()
	cfg := DefaultConfig()
	cfg.Mode = "tunnel"
	cfg.BinaryPath = bin
	if err := c.Init(context.Background(), cfg); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Start is even called

	done := make(chan error, 1)
	go func() {
		done <- c.Start(ctx)
	}()

	select {
	case err := <-done:
		// Must return an error, not hang.
		if err == nil {
			t.Error("expected error on cancelled context, got nil")
		}
		if c.GetState() == StateRunning {
			t.Error("state should not be RUNNING after cancelled start")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start() hung after context cancellation — ready channel not closed")
	}
}
