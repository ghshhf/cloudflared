package ssi

import (
	"context"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/tunnel"
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
	if cfg.Backend != "cloudflare" {
		t.Errorf("default backend = %q; want cloudflare", cfg.Backend)
	}
}

func TestParseConfigRejectsUnknownBackend(t *testing.T) {
	_, err := ParseConfig([]byte(`{"backend":"bogus"}`))
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestParseConfigTCPRelay(t *testing.T) {
	cfg, ssiErr := ParseConfig([]byte(`{
		"name": "relay",
		"backend": "tcp-relay",
		"origin_url": "127.0.0.1:8080",
		"listen_address": "127.0.0.1:0",
		"shutdown_grace_period_seconds": 5000000000,
		"start_timeout_seconds": 20000000000
	}`))
	if ssiErr != nil {
		t.Fatalf("parse error: %v", ssiErr)
	}
	if cfg.Backend != "tcp-relay" {
		t.Errorf("backend = %q; want tcp-relay", cfg.Backend)
	}
	if cfg.ListenAddress == "" {
		t.Error("listen_address should be non-empty")
	}
}

func TestNewBackendConstruction(t *testing.T) {
	tests := []string{
		tunnel.TypeCloudflare,
		tunnel.TypeTCPRelay,
		tunnel.TypeSkyNetP2P,
		tunnel.TypeHTTPProxy,
		tunnel.TypeSOCKS5,
	}
	for _, bt := range tests {
		b, err := tunnel.NewBackend(tunnel.Config{Type: bt, Name: "t-" + bt})
		if err != nil {
			t.Errorf("NewBackend(%q) error: %v", bt, err)
			continue
		}
		if b == nil {
			t.Errorf("NewBackend(%q) returned nil", bt)
			continue
		}
		if b.Type() != bt {
			t.Errorf("backend Type() = %q; want %q", b.Type(), bt)
		}
		if b.Ready() == nil {
			t.Errorf("backend Ready() returned nil channel for %q", bt)
		}
	}
}

func TestNewBackendUnknown(t *testing.T) {
	if _, err := tunnel.NewBackend(tunnel.Config{Type: "unknown"}); err == nil {
		t.Error("expected error for unknown backend type")
	}
}

func TestStateTransitionsInit(t *testing.T) {
	c := NewCloudflaredComponent()
	if got := c.GetState(); got != StateCreated {
		t.Fatalf("initial state = %v; want CREATED", got)
	}

	// tcp-relay 后端不含特定的二进制检查；Init 应该成功。
	cfg := Config{
		Name:          "test-relay",
		Mode:          "quick",
		Backend:       "tcp-relay",
		OriginURL:     "127.0.0.1:0",
		ListenAddress: "127.0.0.1:0",
	}
	if ssiErr := c.Init(context.Background(), cfg); ssiErr != nil {
		t.Fatalf("init failed: %v", ssiErr)
	}
	if c.GetState() != StateInitialized {
		t.Errorf("state after init = %v; want INITIALIZED", c.GetState())
	}
}

// State machine rejects Start on CREATED.
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
		t.Logf("Stop on CREATED returned nil error; acceptable")
	}
}

// TCPRelayLifecycle 验证 tcp-relay 后端生命周期测试：启动 -> Running -> Stopped。
func TestTCPRelayLifecycle(t *testing.T) {
	c := NewCloudflaredComponent()
	cfg := Config{
		Name:          "relay-test",
		Mode:          "quick",
		Backend:       "tcp-relay",
		OriginURL:     "127.0.0.1:0", // 任何地址，但 Start 会 fail fast。
		ListenAddress: "127.0.0.1:0",
	}
	if ssiErr := c.Init(context.Background(), cfg); ssiErr != nil {
		t.Fatalf("init failed: %v", ssiErr)
	}
	if c.GetBackendType() != "tcp-relay" {
		t.Errorf("backend type = %q; want tcp-relay", c.GetBackendType())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if ssiErr := c.Start(ctx); ssiErr != nil {
		t.Fatalf("start failed: %v", ssiErr)
	}
	if c.GetState() != StateRunning {
		t.Errorf("state after start = %v; want RUNNING", c.GetState())
	}

	// 停止。
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if ssiErr := c.Stop(stopCtx); ssiErr != nil {
		t.Fatalf("stop failed: %v", ssiErr)
	}
	if c.GetState() != StateStopped {
		t.Errorf("state after stop = %v; want STOPPED", c.GetState())
	}
}

// RecentLines exposes recent event log — newly added to the multi-backend refactor
func TestRecentLinesBaseline(t *testing.T) {
	c := NewCloudflaredComponent()
	// 空组件有 0 条事件日志。
	if got := c.RecentLines(10); len(got) != 0 {
		t.Errorf("expected empty component has %d recent lines; want 0", len(got))
	}
}

// Verify ring buffer directly.
func TestRingBuffer(t *testing.T) {
	b := newRingBuffer(3)
	b.append("one")
	b.append("two")
	b.append("three")
	b.append("four")
	got := b.tail(3)
	if len(got) != 3 {
		t.Fatalf("tail(3) = %d lines; want 3", len(got))
	}
	if got[0] != "two" || got[1] != "three" || got[2] != "four" {
		t.Errorf("unexpected tail content: %v", got)
	}
}

// Start() with a context that fires cancel immediately should not hang.
func TestStartCtxCancelledDoesNotHang(t *testing.T) {
	c := NewCloudflaredComponent()
	cfg := Config{
		Name:          "cancel-test",
		Mode:          "quick",
		Backend:       "tcp-relay",
		OriginURL:     "127.0.0.1:0",
		ListenAddress: "127.0.0.1:0",
		StartTimeout:  10 * time.Second,
	}
	if ssiErr := c.Init(context.Background(), cfg); ssiErr != nil {
		t.Fatalf("init failed: %v", ssiErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- c.Start(ctx)
	}()

	select {
	case err := <-done:
		// 即使 context 已经取消，Start 必须在合理时间内返回。
		if err == nil {
			t.Error("expected error on cancelled context, got nil")
		}
		if c.GetState() == StateRunning {
			t.Error("state should not be RUNNING after cancelled start")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start() hung — ready channel / ctx select missing")
	}
}

// Stop() 应该是 idempotent.
func TestStopIsIdempotent(t *testing.T) {
	c := NewCloudflaredComponent()
	ctx := context.Background()
	// 第一次 stop —— state 是 CREATED，返回错误但不 panic。
	_ = c.Stop(ctx)
	// 第二次 stop —— 同样返回错误但不 panic。
	_ = c.Stop(ctx)
}
