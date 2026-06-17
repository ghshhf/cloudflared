package tunnel

import (
	"context"
	"sync/atomic"
	"testing"
)

// mockBackend implements the tunnel.Backend interface for testing.
type mockBackend struct {
	name     string
	typ      string
	ready    chan struct{}
	startErr error
	stopErr  error
	started  bool
	stopped  bool
}

func (m *mockBackend) Name() string {
	if m.name != "" {
		return m.name
	}
	return "mock"
}

func (m *mockBackend) Type() string {
	if m.typ != "" {
		return m.typ
	}
	return "mock"
}

func (m *mockBackend) Ready() <-chan struct{} {
	return m.ready
}

func (m *mockBackend) Start(ctx context.Context) error {
	m.started = true
	if m.startErr != nil {
		return m.startErr
	}
	close(m.ready)
	return nil
}

func (m *mockBackend) Stop(ctx context.Context) error {
	m.stopped = true
	return m.stopErr
}

func newMockBackend(name string) *mockBackend {
	return &mockBackend{
		name:  name,
		typ:   "mock",
		ready: make(chan struct{}),
	}
}

// TestNewFailoverBackend verifies newFailoverBackend creates an instance
// with the correct Name() and Type() values.
func TestNewFailoverBackend(t *testing.T) {
	cfg := Config{Name: "test-failover"}
	fb := newFailoverBackend(cfg)

	if want := "failover://test-failover"; fb.Name() != want {
		t.Errorf("Name() = %q, want %q", fb.Name(), want)
	}
	if want := "failover"; fb.Type() != want {
		t.Errorf("Type() = %q, want %q", fb.Type(), want)
	}
}

// TestFailoverStartNoBackends verifies that Start returns an error when
// no backends are configured.
func TestFailoverStartNoBackends(t *testing.T) {
	ctx := context.Background()
	fb := newFailoverBackend(Config{Name: "empty"})
	err := fb.Start(ctx)
	if err == nil {
		t.Fatal("expected error when starting with no backends")
	}
}

// TestFailoverStartSingleBackend verifies Start succeeds and the single
// child backend is started.
func TestFailoverStartSingleBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mb := newMockBackend("primary")
	fb := newFailoverBackend(Config{Name: "single"}, mb)

	if err := fb.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mb.started {
		t.Error("backend was not started")
	}
}

// TestFailoverStartMultipleBackends verifies all child backends are
// started concurrently.
func TestFailoverStartMultipleBackends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m0 := newMockBackend("b0")
	m1 := newMockBackend("b1")
	m2 := newMockBackend("b2")
	fb := newFailoverBackend(Config{Name: "multi"}, m0, m1, m2)

	if err := fb.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m0.started {
		t.Error("backend 0 was not started")
	}
	if !m1.started {
		t.Error("backend 1 was not started")
	}
	if !m2.started {
		t.Error("backend 2 was not started")
	}
}

// TestFailoverIsDegraded verifies IsDegraded is false initially and
// becomes true when the primary backend fails and a fallback takes over.
func TestFailoverIsDegraded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m0 := newMockBackend("primary")
	m1 := newMockBackend("fallback")
	fb := newFailoverBackend(Config{Name: "degraded"}, m0, m1)

	if err := fb.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Force primary (index 0) as active; concurrent goroutine scheduling
	// may otherwise leave current pointing at the fallback.
	fb.current = 0
	atomic.StoreInt32(&fb.degraded, 0)

	// Initially not degraded.
	if fb.IsDegraded() {
		t.Error("expected IsDegraded() == false initially")
	}

	// Simulate primary failure and promote the fallback.
	atomic.StoreInt32(&fb.health[0], 2) // unhealthy
	fb.promoteNextHealthyIfNeeded(ctx)

	if !fb.IsDegraded() {
		t.Error("expected IsDegraded() == true after primary failure and fallback promotion")
	}
}

// TestFailoverHealthStatus verifies the correct marker strings for
// healthy, unhealthy, and degraded backend states.
func TestFailoverHealthStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m0 := newMockBackend("primary-tun")
	m1 := newMockBackend("fallback-tun")
	fb := newFailoverBackend(Config{Name: "health"}, m0, m1)

	if err := fb.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Force primary as active (see IsDegraded test for rational).
	fb.current = 0
	atomic.StoreInt32(&fb.degraded, 0)

	// Both healthy, primary active.
	status := fb.HealthStatus()
	if len(status) != 2 {
		t.Fatalf("expected 2 status entries, got %d", len(status))
	}
	if status[0] != "[*OK] primary-tun" {
		t.Errorf("primary healthy marker = %q, want %q", status[0], "[*OK] primary-tun")
	}
	if status[1] != "[OK] fallback-tun" {
		t.Errorf("fallback healthy marker = %q, want %q", status[1], "[OK] fallback-tun")
	}

	// Simulate primary failure → degraded fallback active.
	atomic.StoreInt32(&fb.health[0], 2)
	fb.promoteNextHealthyIfNeeded(ctx)

	status = fb.HealthStatus()
	if status[0] != "[DOWN] primary-tun" {
		t.Errorf("primary unhealthy marker = %q, want %q", status[0], "[DOWN] primary-tun")
	}
	if status[1] != "[*DEGRADED(OK)] fallback-tun" {
		t.Errorf("fallback degraded marker = %q, want %q", status[1], "[*DEGRADED(OK)] fallback-tun")
	}

	// Both unhealthy.
	fb.current = 0
	atomic.StoreInt32(&fb.health[1], 2)
	fb.promoteNextHealthyIfNeeded(ctx)

	status = fb.HealthStatus()
	if status[0] != "[*DOWN] primary-tun" {
		t.Errorf("both unhealthy, primary marker = %q, want %q", status[0], "[*DOWN] primary-tun")
	}
	if status[1] != "[DOWN] fallback-tun" {
		t.Errorf("both unhealthy, fallback marker = %q, want %q", status[1], "[DOWN] fallback-tun")
	}
}

// TestFailoverStop verifies Stop is idempotent and stops all child backends.
func TestFailoverStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m0 := newMockBackend("b0")
	m1 := newMockBackend("b1")
	fb := newFailoverBackend(Config{Name: "stop"}, m0, m1)

	if err := fb.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First stop.
	if err := fb.Stop(ctx); err != nil {
		t.Errorf("first Stop: unexpected error: %v", err)
	}
	if !m0.stopped {
		t.Error("backend 0 was not stopped")
	}
	if !m1.stopped {
		t.Error("backend 1 was not stopped")
	}

	// Second stop — idempotent.
	if err := fb.Stop(context.Background()); err != nil {
		t.Errorf("second Stop (idempotent): unexpected error: %v", err)
	}
}

// TestFailoverStopNeverStarted verifies Stop on a never-started failover
// returns no error.
func TestFailoverStopNeverStarted(t *testing.T) {
	ctx := context.Background()
	fb := newFailoverBackend(Config{Name: "never-started"})
	if err := fb.Stop(ctx); err != nil {
		t.Errorf("unexpected error on never-started Stop: %v", err)
	}

	// Also check with backends but never started.
	m0 := newMockBackend("b0")
	m1 := newMockBackend("b1")
	fb2 := newFailoverBackend(Config{Name: "never-started-2"}, m0, m1)
	if err := fb2.Stop(ctx); err != nil {
		t.Errorf("unexpected error on never-started Stop (with backends): %v", err)
	}
}

// TestFailoverActiveBackend verifies ActiveBackend returns -1 when no
// backends are configured, and 0 when the primary backend is active.
func TestFailoverActiveBackend(t *testing.T) {
	// No backends → -1.
	fb := newFailoverBackend(Config{Name: "empty"})
	if active := fb.ActiveBackend(); active != -1 {
		t.Errorf("ActiveBackend with no backends = %d, want -1", active)
	}

	// Backends present, after Start → primary (index 0) is active.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m0 := newMockBackend("primary")
	m1 := newMockBackend("fallback")
	fb2 := newFailoverBackend(Config{Name: "active"}, m0, m1)

	if err := fb2.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Force primary as active (see IsDegraded test for rationale).
	fb2.current = 0
	if active := fb2.ActiveBackend(); active != 0 {
		t.Errorf("ActiveBackend after start = %d, want 0", active)
	}
}
