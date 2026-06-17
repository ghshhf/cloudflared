package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// failoverBackend implements multi-tunnel aggregation with automatic
// failover. It maintains a list of child backends, keeps track of each
// one's health, and directs traffic to the first healthy backend.
//
// Example topology:
//
//   backends[0] = cloudflare tunnel (primary, high reliability)
//   backends[1] = proxy-pool (fallback, free proxy pool)
//   backends[2] = tcp relay (last-resort, self-hosted)
//
// On Start, all backends are launched concurrently. Traffic always goes
// through the front-most healthy backend; when a backend is marked
// unhealthy, the next one takes over.
//
// Degraded mode: when the active backend is NOT the primary (index 0),
// the failover aggregate is considered "degraded". This is visible via
// IsDegraded() and in metrics. Degraded mode is cleared when the primary
// backend recovers.
type failoverBackend struct {
	cfg       Config
	backends  []Backend
	ready     chan struct{}
	stopped   bool
	mu        sync.Mutex

	// current indexes into backends for the currently active backend.
	// Accessed atomically from producers and consumers.
	current int32

	// health tracks per-backend health status (0 = unknown,
	// 1 = healthy, 2 = unhealthy).
	health []int32

	// degraded is true when a non-primary backend is active.
	degraded int32 // atomic bool (0 = false, 1 = true)

	// acceptListener is only set when the aggregate backends are
	// TCP-listening (TCPRelay, HTTP proxy, SOCKS5).
	acceptListener net.Listener
}

// newFailoverBackend creates a failover aggregator. The cfg argument
// describes the aggregate itself; backends are supplied separately.
func newFailoverBackend(cfg Config, backends ...Backend) *failoverBackend {
	return &failoverBackend{
		cfg:    cfg,
		backends: backends,
		ready:  make(chan struct{}),
		health: make([]int32, len(backends)),
	}
}

func (b *failoverBackend) Name() string { return "failover://" + b.cfg.Name }
func (b *failoverBackend) Type() string { return "failover" }
func (b *failoverBackend) Ready() <-chan struct{} { return b.ready }

// Start launches all child backends concurrently. The aggregate is
// considered "ready" as soon as at least one child is ready.
func (b *failoverBackend) Start(ctx context.Context) error {
	if len(b.backends) == 0 {
		return &backendErr{msg: "failover: no backends configured"}
	}

	// Launch each backend in its own goroutine.
	errCh := make(chan error, len(b.backends))
	for i, be := range b.backends {
		beName := be.Name()
		go func(idx int, backend Backend) {
			if err := backend.Start(ctx); err != nil {
				atomic.StoreInt32(&b.health[idx], 2) // unhealthy
				metrics.SetAvailable(beName, false)
				metrics.RecordError("failover")
				errCh <- err
				return
			}
			// Wait for the backend to signal readiness.
			select {
			case <-backend.Ready():
				atomic.StoreInt32(&b.health[idx], 1) // healthy
				metrics.SetAvailable(beName, true)
				metrics.SetAvailable("failover", true)
				errCh <- nil
			case <-ctx.Done():
				atomic.StoreInt32(&b.health[idx], 2)
				metrics.SetAvailable(beName, false)
				errCh <- ctx.Err()
			}
		}(i, be)
	}

	// Wait for first healthy backend; continue to receive the others'
	// results silently (they will be part of the pool regardless).
	var readyCount int
	var firstErr error
	for range b.backends {
		select {
		case err := <-errCh:
			if err == nil {
				readyCount++
				// If no backend has been chosen yet, pick this one.
				if atomic.LoadInt32(&b.current) == 0 && atomic.CompareAndSwapInt32(&b.current, 0, int32(indexOfHealthy(b.health))) {
					// first backend became healthy; if it is index 0 we're good
				}
				// If this is the first time we reach >=1 healthy backends,
				// broadcast readiness.
				select {
				case <-b.ready:
					// already closed
				default:
					close(b.ready)
				}
			} else if firstErr == nil {
				firstErr = err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if readyCount == 0 {
		if firstErr != nil {
			return fmt.Errorf("failover: all backends failed — first: %w", firstErr)
		}
		return &backendErr{msg: "failover: no backend became ready"}
	}

	// Start background health checker.
	go b.healthChecker(ctx)

	return nil
}

// indexOfHealthy scans b.health and returns the index of the first
// healthy backend. If nothing is healthy, it returns 0 (callers check
// readiness separately).
func indexOfHealthy(health []int32) int {
	for i, h := range health {
		if h == 1 {
			return i
		}
	}
	return 0
}

// healthChecker periodically switches to another backend if the current
// one appears to have died. It relies on each backend's Ready() channel
// and process exit signal to determine health status.
func (b *failoverBackend) healthChecker(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.promoteNextHealthyIfNeeded(ctx)
		}
	}
}

func (b *failoverBackend) promoteNextHealthyIfNeeded(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	current := atomic.LoadInt32(&b.current)
	if current < 0 || int(current) >= len(b.backends) {
		return
	}
	// Check if current is still healthy.
	health := atomic.LoadInt32(&b.health[current])
	if health == 1 {
		// Primary recovered — clear degraded.
		if current == 0 && atomic.LoadInt32(&b.degraded) == 1 {
			atomic.StoreInt32(&b.degraded, 0)
			metrics.SetAvailable("failover-degraded", false)
		}
		return
	}
	// Search for next healthy backend after current (wrapping to start).
	for offset := 1; offset <= len(b.backends); offset++ {
		idx := (int(current) + offset) % len(b.backends)
		if atomic.LoadInt32(&b.health[idx]) == 1 {
			atomic.StoreInt32(&b.current, int32(idx))
			// Mark degraded if switched to a non-primary backend.
			if idx != 0 {
				atomic.StoreInt32(&b.degraded, 1)
				metrics.SetAvailable("failover-degraded", true)
				// Notify via metrics which fallback is active.
				metrics.RecordFailover("failover")
				metrics.RecordFailover(b.backends[idx].Name())
			}
			return
		}
	}
	// No healthy backend — mark failover aggregate as unavailable.
	metrics.SetAvailable("failover", false)
}

// ActiveBackend returns the currently active backend index; -1 if none.
func (b *failoverBackend) ActiveBackend() int {
	active := atomic.LoadInt32(&b.current)
	if active < 0 || int(active) >= len(b.backends) {
		return -1
	}
	return int(active)
}

// IsDegraded returns true when a non-primary backend is active.
func (b *failoverBackend) IsDegraded() bool {
	return atomic.LoadInt32(&b.degraded) == 1
}

// Stop stops all child backends in parallel.
func (b *failoverBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	b.stopped = true
	b.mu.Unlock()

	errCh := make(chan error, len(b.backends))
	for _, be := range b.backends {
		go func(backend Backend) {
			errCh <- backend.Stop(ctx)
		}(be)
	}

	var firstErr error
	for range b.backends {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// HealthStatus returns a snapshot of backend health for display.
func (b *failoverBackend) HealthStatus() []string {
	out := make([]string, len(b.backends))
	for i, be := range b.backends {
		h := atomic.LoadInt32(&b.health[i])
		marker := "?"
		switch h {
		case 1:
			marker = "OK"
		case 2:
			marker = "DOWN"
		}
		if int(atomic.LoadInt32(&b.current)) == i {
			if i == 0 {
				marker = "*" + marker
			} else {
				marker = "*DEGRADED(" + marker + ")"
			}
		}
		out[i] = fmt.Sprintf("[%s] %s", marker, be.Name())
	}
	return out
}
