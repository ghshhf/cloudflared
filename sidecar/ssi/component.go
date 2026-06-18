// Package ssi: implementation of the SkyNet SSI component lifecycle
// for the cloudflared sidecar.
//
// The struct here is called CloudflaredComponent for historical reasons —
// originally it only knew how to fork the cloudflared binary. Today it
// delegates all traffic work to the pluggable Backend interface (see
// the tunnel package). This means the same component now supports:
//
//   - cloudflare  → fork the official binary (default)
//   - tcp-relay   → simple self-hosted TCP forwarder
//   - skynet-p2p  → device-to-device over the SkyNet peer-to-peer layer
//   - http-proxy  → local HTTP CONNECT proxy over the active tunnel
//   - socks5      → local SOCKS5 proxy over the active tunnel
package ssi

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/tunnel"
)

// CloudflaredComponent is the SSI wrapper around a single backend.
// One instance manages exactly one tunnel.
type CloudflaredComponent struct {
	mu sync.RWMutex

	state ComponentState
	cfg   Config

	// backend is the active traffic backend. Set in Init() and
	// replaced when the component cycles Init/Start again.
	backend tunnel.Backend

	// logs is a lightweight ring buffer for the sidecar's own event
	// log (state transitions, warnings). Kept separate from child
	// process output so each backend can choose its own log
	// strategy.
	logs *ringBuffer
}

// NewCloudflaredComponent constructs a component in the CREATED state.
func NewCloudflaredComponent() *CloudflaredComponent {
	return &CloudflaredComponent{
		state: StateCreated,
		logs:  newRingBuffer(256),
	}
}

// RecentLines returns the most recent N lines of the sidecar's own
// event log. This is the get_logs RPC data source — keep it cheap.
func (c *CloudflaredComponent) RecentLines(n int) []string {
	if c == nil || c.logs == nil {
		return nil
	}
	return c.logs.tail(n)
}

// logLine appends a line to the component's event ring buffer. Safe
// to call concurrently.
func (c *CloudflaredComponent) logLine(format string, args ...any) {
	if c == nil || c.logs == nil {
		return
	}
	c.logs.append(fmt.Sprintf("[%s] %s", time.Now().UTC().Format("15:04:05"), fmt.Sprintf(format, args...)))
}

// Init validates the configuration and constructs a backend based on
// cfg.Backend. We do not start any process here so the runtime can
// keep initialising other components in parallel.
func (c *CloudflaredComponent) Init(ctx context.Context, cfg Config) *SsiError {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state >= StateInitializing {
		return &SsiError{Code: ErrInvalidState, Message: "already initialised (state=" + c.state.String() + ")"}
	}
	c.state = StateInitializing

	// Map the IPC-level Config to the backend-level tunnel.Config.
	// Keeping the two types separate lets the IPC wire format stay
	// stable even as we add more backend-specific knobs.
	tcfg := tunnel.Config{
		Type:                       cfg.Backend,
		Name:                       cfg.Name,
		OriginURL:                  cfg.OriginURL,
		CloudflareMode:             cfg.Mode,
		CloudflareBinary:           cfg.BinaryPath,
		ListenAddress:              cfg.ListenAddress,
		RelayTarget:                cfg.RelayTarget,
		ProxyListen:                cfg.ProxyListen,
		ExtraArgs:                  cfg.ExtraArgs,
		AccessHostname:             cfg.Hostname,
		AccessDestination:          cfg.Destination,
		StartTimeoutSeconds:        float64(cfg.StartTimeout.Seconds()),
		ShutdownGracePeriodSeconds: float64(cfg.ShutdownGracePeriod.Seconds()),
	}

	if tcfg.Name == "" {
		tcfg.Name = "cloudflared-default"
	}
	if tcfg.Type == "" {
		tcfg.Type = tunnel.TypeCloudflare
	}

	b, err := tunnel.NewBackend(tcfg)
	if err != nil {
		c.state = StateError
		return &SsiError{Code: ErrConfigInvalid, Message: err.Error()}
	}
	c.backend = b
	c.cfg = cfg
	c.state = StateInitialized
	return nil
}

// Start brings up the backend. Blocks until the backend reports ready,
// the context expires, or the startup timeout elapses.
func (c *CloudflaredComponent) Start(ctx context.Context) *SsiError {
	c.mu.Lock()
	if c.state != StateInitialized && c.state != StateStopped && c.state != StatePaused {
		defer c.mu.Unlock()
		return &SsiError{Code: ErrInvalidState, Message: "cannot start from state " + c.state.String()}
	}
	if c.backend == nil {
		defer c.mu.Unlock()
		return &SsiError{Code: ErrInvalidState, Message: "not initialised — call init first"}
	}
	startTimeout := c.cfg.StartTimeout
	if startTimeout <= 0 {
		startTimeout = 30 * time.Second
	}
	c.state = StateStarting
	c.mu.Unlock()

	// Start is a blocking call on the backend; it returns nil when the
	// tunnel is up or an error if it never came up. We wrap this in a
	// goroutine so the caller can cancel via ctx.
	startErr := make(chan error, 1)
	go func() {
		startErr <- c.backend.Start(ctx)
	}()

	select {
	case err := <-startErr:
		if err != nil {
			c.mu.Lock()
			c.state = StateError
			c.mu.Unlock()
			return &SsiError{Code: ErrProcessStart, Message: err.Error()}
		}
		c.mu.Lock()
		c.state = StateRunning
		c.mu.Unlock()
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		c.state = StateError
		c.mu.Unlock()
		// Best-effort: ask backend to stop; swallow the stop-error
		// because the caller already knows about the cancellation.
		_ = c.backend.Stop(context.Background())
		return &SsiError{Code: ErrProcessStart, Message: "start cancelled: " + ctx.Err().Error()}
	case <-time.After(startTimeout):
		c.mu.Lock()
		c.state = StateError
		c.mu.Unlock()
		_ = c.backend.Stop(context.Background())
		return &SsiError{Code: ErrProcessStart, Message: "start timeout after " + startTimeout.String()}
	}
}

// Stop tears down the backend. Idempotent — safe to call multiple
// times.
func (c *CloudflaredComponent) Stop(ctx context.Context) *SsiError {
	c.mu.Lock()
	if c.state != StateRunning && c.state != StatePaused && c.state != StateStarting {
		defer c.mu.Unlock()
		return &SsiError{Code: ErrInvalidState, Message: "not running (state=" + c.state.String() + ")"}
	}
	c.state = StateStopping
	backend := c.backend
	c.mu.Unlock()

	if backend == nil {
		c.mu.Lock()
		c.state = StateStopped
		c.mu.Unlock()
		return nil
	}

	// Give the backend a bounded time to stop cleanly; fall back to a
	// forced kill via the parent context deadline if it drags its feet.
	stopCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		stopCtx, cancel = context.WithTimeout(context.Background(), c.cfg.ShutdownGracePeriod)
		defer cancel()
	}
	if err := backend.Stop(stopCtx); err != nil {
		c.mu.Lock()
		c.state = StateError
		c.mu.Unlock()
		return &SsiError{Code: ErrProcessStop, Message: err.Error()}
	}
	c.mu.Lock()
	c.state = StateStopped
	c.mu.Unlock()
	return nil
}

// Pause maps cleanly to "stop the traffic but keep the configuration"
// — that is exactly Stop with a different state marker.
func (c *CloudflaredComponent) Pause(ctx context.Context) *SsiError {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	if state != StateRunning {
		return &SsiError{Code: ErrInvalidState, Message: "cannot pause from " + state.String()}
	}
	if err := c.Stop(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.state = StatePaused
	c.mu.Unlock()
	return nil
}

// Resume from PAUSED is simply another Start() — the configuration is
// still attached to the component.
func (c *CloudflaredComponent) Resume(ctx context.Context) *SsiError {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	if state != StatePaused {
		return &SsiError{Code: ErrInvalidState, Message: "cannot resume from " + state.String()}
	}
	c.mu.Lock()
	c.state = StateResuming
	c.mu.Unlock()
	return c.Start(ctx)
}

// GetState returns the current lifecycle state. Safe to call concurrently.
func (c *CloudflaredComponent) GetState() ComponentState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// GetBackendType returns the canonical backend type for inspection
// (e.g. "cloudflare", "tcp-relay", "skynet-p2p"). Useful for the
// IPC "status" response and the web UI.
func (c *CloudflaredComponent) GetBackendType() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.backend == nil {
		return ""
	}
	return c.backend.Type()
}

// GetBackendName returns the human-friendly backend name, e.g.
// "cloudflare://my-tunnel".
func (c *CloudflaredComponent) GetBackendName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.backend == nil {
		return ""
	}
	return c.backend.Name()
}

// String renders a one-line summary used by the IPC bus and the web UI.
func (c *CloudflaredComponent) String() string {
	be := c.GetBackendType()
	if be == "" {
		be = "(no backend)"
	}
	return c.GetState().String() + " [" + be + "] " + c.GetBackendName()
}

// Sanity helpers for callers that want to branch on the backend
// (e.g. the web UI exposes extra stats for tcp-relay). We keep these
// here so callers do not need to import the tunnel package.

// IsTCPRelay returns true if the configured backend is a TCP relay.
func (c *CloudflaredComponent) IsTCPRelay() bool { return c.GetBackendType() == tunnel.TypeTCPRelay }

// IsCloudflare returns true for the default cloudflared backend.
func (c *CloudflaredComponent) IsCloudflare() bool {
	return c.GetBackendType() == tunnel.TypeCloudflare
}

// IsSkyNetP2P returns true for the peer-to-peer backend.
func (c *CloudflaredComponent) IsSkyNetP2P() bool { return c.GetBackendType() == tunnel.TypeSkyNetP2P }

// IsHTTPProxy returns true for the HTTP CONNECT proxy backend.
func (c *CloudflaredComponent) IsHTTPProxy() bool { return c.GetBackendType() == tunnel.TypeHTTPProxy }

// IsSOCKS5 returns true for the SOCKS5 proxy backend.
func (c *CloudflaredComponent) IsSOCKS5() bool { return c.GetBackendType() == tunnel.TypeSOCKS5 }

// IsFailover returns true for the multi-backend failover aggregator.
func (c *CloudflaredComponent) IsFailover() bool { return c.GetBackendType() == "failover" }

// ---- Component adapter for the embedded web dashboard -----------------
// These methods exist so the dashboard package can consume a
// lightweight interface without importing the concrete CloudflaredComponent
// type.

func (c *CloudflaredComponent) Name() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cfg.Name == "" {
		return "cloudflared-sidecar"
	}
	return c.cfg.Name
}

// State returns the human-readable lifecycle state name.
func (c *CloudflaredComponent) State() string { return c.GetState().String() }

// BackendType returns the backend type name ("cloudflare", "tcp-relay", …).
// Empty string if Init() has not been called.
func (c *CloudflaredComponent) BackendType() string { return c.GetBackendType() }

// BackendName returns the backend's Name() for display. Empty string when
// Init() has not been called.
func (c *CloudflaredComponent) BackendName() string { return c.GetBackendName() }

// PoolStats returns proxy pool statistics if the active backend is a proxy-pool.
// Returns nil when the backend is not a proxy-pool or when Init() has not been
// called. Implements the dashboard.PoolStatsProvider interface.
func (c *CloudflaredComponent) PoolStats() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.backend == nil || c.backend.Type() != tunnel.TypeProxyPool {
		return nil
	}
	// The proxyPoolBackend has a PoolStats() method; access it via interface.
	type poolStatser interface{ PoolStats() map[string]any }
	if ps, ok := c.backend.(poolStatser); ok {
		return ps.PoolStats()
	}
	return nil
}

// ---- utility -----------------------------------------------------------

// hasPrefix is a tiny helper used by IPC bus handlers to route requests.
func hasPrefix(s, prefix string) bool { return strings.HasPrefix(s, prefix) }

// ringBuffer is a lightweight concurrent-safe ring buffer of log lines.
// Cap is bounded by the size supplied to newRingBuffer.
type ringBuffer struct {
	mu    sync.RWMutex
	lines []string
	cap   int
}

func newRingBuffer(cap int) *ringBuffer { return &ringBuffer{cap: cap} }

func (r *ringBuffer) append(line string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
	if r.cap > 0 && len(r.lines) > r.cap {
		r.lines = r.lines[len(r.lines)-r.cap:]
	}
}

func (r *ringBuffer) tail(n int) []string {
	if r == nil || n <= 0 {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.lines) == 0 {
		return nil
	}
	if n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}
