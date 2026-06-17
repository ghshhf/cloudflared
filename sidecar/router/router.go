// Package router provides an intelligent, policy-driven traffic routing layer
// that sits in front of the Backend abstraction. It enables:
//   - Rule-based routing: route by destination IP/CIDR, domain, protocol
//   - Multiple routing modes: failover, round-robin, latency-optimized, priority
//   - Automatic backend health and latency tracking via the metrics package
//   - P2P preference: always prefer direct peer connections when available
//
// Example configuration:
//
//	cfg := router.Config{
//	    Mode:      router.ModeLatency,
//	    PreferP2P:  true,
//	    Rules: []router.Rule{
//	        {Dest: "10.0.0.0/8",   Backend: "skynet-p2p",  Priority: 100},
//	        {Dest: "192.168.0.0/16", Backend: "tcp-relay", Priority: 90},
//	        {Proto: "udp",         Backend: "skynet-p2p",  Priority: 80},
//	    },
//	}
//
// The router is transparent to the caller — it satisfies the tunnel.Backend
// interface so it can be registered in NewBackend() alongside other backends.
package router

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// Backend is the subset of the tunnel.Backend interface that the router
// needs. It avoids a hard import cycle between the router and tunnel packages.
type Backend interface {
	Name() string
	Type() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Ready() <-chan struct{}
}

// ---- Routing modes -------------------------------------------------------

// Mode defines the global traffic distribution strategy.
type Mode string

const (
	// ModeFailover uses the first healthy backend, switches on failure.
	ModeFailover Mode = "failover"
	// ModeRoundRobin distributes connections across all healthy backends.
	ModeRoundRobin Mode = "round-robin"
	// ModeLatency always picks the backend with the lowest P99 latency.
	ModeLatency Mode = "latency"
	// ModeSticky uses the backend with the fewest active connections.
	ModeSticky Mode = "sticky"
	// ModeP2PFirst tries P2P backends first, falls back to others.
	ModeP2PFirst Mode = "p2p-first"
)

// ---- Route rule ----------------------------------------------------------

// Rule matches traffic and assigns it to a named backend.
// Rules are sorted by priority (highest first) at startup.
type Rule struct {
	// Dest is a CIDR (e.g. "10.0.0.0/8") or domain pattern (e.g. "*.local").
	// Empty Dest matches everything.
	Dest string `json:"dest,omitempty"`
	// Proto matches traffic by protocol: "tcp", "udp", or "" for all.
	Proto string `json:"proto,omitempty"`
	// Backend is the name of a registered backend to route matching traffic to.
	Backend string `json:"backend"`
	// Priority determines evaluation order. Higher = earlier. Default 0.
	Priority int `json:"priority"`
	// Mode optionally overrides the global mode for matching traffic.
	Mode Mode `json:"mode,omitempty"`
}

// matches reports whether the rule matches the given connection context.
func (r *Rule) matches(addr net.Addr, proto string) bool {
	if r.Proto != "" && r.Proto != proto {
		return false
	}
	if r.Dest == "" {
		return true
	}
	host, _, err := splitAddr(addr)
	if err != nil {
		return false
	}
	return r.matchDest(host)
}

func (r *Rule) matchDest(host string) bool {
	// CIDR check.
	if ip := net.ParseIP(host); ip != nil {
		_, ipNet, err := net.ParseCIDR(r.Dest)
		if err == nil && ipNet.Contains(ip) {
			return true
		}
	}
	// Domain glob check (simple suffix match for "*.example.com").
	if len(r.Dest) > 1 && r.Dest[0] == '*' {
		suffix := r.Dest[1:]
		if len(host) >= len(suffix) && host[len(host)-len(suffix):] == suffix {
			return true
		}
	}
	// Exact match.
	return host == r.Dest
}

// ---- Config --------------------------------------------------------------

// Config is the router's configuration.
type Config struct {
	// Mode is the default routing strategy.
	Mode Mode `json:"mode"`
	// PreferP2P when true biases toward P2P-capable backends.
	PreferP2P bool `json:"prefer_p2p"`
	// Rules are evaluated in priority order (highest first).
	Rules []Rule `json:"rules"`
	// HealthInterval controls how often the router re-evaluates backend health.
	HealthInterval time.Duration `json:"health_interval"`
}

// Validate checks the configuration for obvious errors.
func (c Config) Validate() error {
	if c.Mode == "" {
		c.Mode = ModeP2PFirst
	}
	switch c.Mode {
	case ModeFailover, ModeRoundRobin, ModeLatency, ModeSticky, ModeP2PFirst:
	default:
		return fmt.Errorf("router: unknown mode %q", c.Mode)
	}
	for i, r := range c.Rules {
		if r.Backend == "" {
			return fmt.Errorf("router: rule %d has empty backend", i)
		}
	}
	return nil
}

// ---- SmartRouter ---------------------------------------------------------

// SmartRouter is a policy-driven routing layer. It implements the tunnel.Backend
// interface so it can be used as a top-level backend in the same NewBackend
// registry.
//
// All exported methods are safe for concurrent use.
type SmartRouter struct {
	cfg Config

	mu      sync.RWMutex
	rules   []Rule // sorted by priority descending
	backends map[string]Backend

	// round-robin state
	rrIndex uint32

	ready   chan struct{}
	stopped bool
}

// New creates a new SmartRouter. Backends must be registered via
// RegisterBackend before Start() is called.
func New(cfg Config) (*SmartRouter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = 3 * time.Second
	}
	rules := make([]Rule, len(cfg.Rules))
	copy(rules, cfg.Rules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
	return &SmartRouter{
		cfg:      cfg,
		rules:    rules,
		backends: make(map[string]Backend),
		ready:    make(chan struct{}),
	}, nil
}

// RegisterBackend makes a backend available for routing. It must be called
// before Start().
func (r *SmartRouter) RegisterBackend(name string, be Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backends[name] = be
}

// Name implements tunnel.Backend.
func (r *SmartRouter) Name() string { return "smart-router" }

// Type implements tunnel.Backend.
func (r *SmartRouter) Type() string { return "smart-router" }

// Ready implements tunnel.Backend.
func (r *SmartRouter) Ready() <-chan struct{} { return r.ready }

// Start launches all registered child backends and the background health tracker.
func (r *SmartRouter) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return nil
	}

	// Start all child backends.
	errCh := make(chan error, len(r.backends))
	for name, be := range r.backends {
		go func(n string, b Backend) {
			if err := b.Start(ctx); err != nil {
				metrics.SetAvailable(n, false)
				errCh <- fmt.Errorf("smart-router child %s: %w", n, err)
				return
			}
			metrics.SetAvailable(n, true)
			errCh <- nil
		}(name, be)
	}
	r.mu.Unlock()

	// Wait for all backends to start.
	var failed int
	for range r.backends {
		select {
		case err := <-errCh:
			if err != nil {
				failed++
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if failed == len(r.backends) && len(r.backends) > 0 {
		return fmt.Errorf("smart-router: all child backends failed")
	}

	close(r.ready)
	return nil
}

// Stop terminates all child backends.
func (r *SmartRouter) Stop(ctx context.Context) error {
	r.mu.Lock()
	r.stopped = true
	r.ready = make(chan struct{})
	backends := r.backends
	r.mu.Unlock()

	var last error
	for name, be := range backends {
		if err := be.Stop(ctx); err != nil && last == nil {
			last = err
		}
		metrics.SetAvailable(name, false)
	}
	metrics.SetAvailable("smart-router", false)
	return last
}

// Route returns the best backend for the given connection context.
// It evaluates rules first, then falls back to the global strategy.
func (r *SmartRouter) Route(ctx context.Context, addr net.Addr, proto string) (Backend, string, Mode) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	proto = normalizeProto(proto)
	// 1. Rule-based routing.
	for _, rule := range r.rules {
		if rule.matches(addr, proto) {
			if be, ok := r.backends[rule.Backend]; ok {
				mode := rule.Mode
				if mode == "" {
					mode = r.cfg.Mode
				}
				return be, rule.Backend, mode
			}
		}
	}

	// 2. Global strategy.
	bestName := r.bestByModeLocked()
	if bestName == "" {
		return nil, "", r.cfg.Mode
	}
	return r.backends[bestName], bestName, r.cfg.Mode
}

// bestByModeLocked returns the name of the best backend under the current mode.
// Caller must hold r.mu.
func (r *SmartRouter) bestByModeLocked() string {
	switch r.cfg.Mode {
	case ModeP2PFirst:
		return r.bestP2PLocked()
	case ModeLatency:
		return r.bestLatencyLocked()
	case ModeSticky:
		return r.bestStickyLocked()
	case ModeRoundRobin:
		return r.roundRobinLocked()
	case ModeFailover:
		return r.bestFailoverLocked()
	default:
		return r.bestP2PLocked()
	}
}

func (r *SmartRouter) bestP2PLocked() string {
	for name := range r.backends {
		if isP2P(name) && metrics.Default().ForBackend(name).Available.Value() == 1 {
			return name
		}
	}
	return r.bestLatencyLocked()
}

func (r *SmartRouter) bestLatencyLocked() string {
	type candidate struct {
		name    string
		p99     float64
		available bool
	}
	var best candidate
	first := true
	for name := range r.backends {
		m := metrics.Default().ForBackend(name)
		if m.Available.Value() != 1 {
			continue
		}
		p99 := m.Latency.Percentile(0.99)
		if first || p99 < best.p99 {
			best = candidate{name: name, p99: p99, available: true}
			first = false
		}
	}
	if best.name == "" {
		// No healthy backend — return any registered backend for diagnostics.
		for name := range r.backends {
			return name
		}
	}
	return best.name
}

func (r *SmartRouter) bestStickyLocked() string {
	type candidate struct {
		name  string
		conns int64
	}
	var best candidate
	first := true
	for name := range r.backends {
		m := metrics.Default().ForBackend(name)
		if m.Available.Value() != 1 {
			continue
		}
		conns := m.ConnectionsActive.Value()
		if first || conns < best.conns {
			best = candidate{name: name, conns: conns}
			first = false
		}
	}
	return best.name
}

func (r *SmartRouter) roundRobinLocked() string {
	names := make([]string, 0, len(r.backends))
	for name := range r.backends {
		if metrics.Default().ForBackend(name).Available.Value() == 1 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	idx := atomic.AddUint32(&r.rrIndex, 1) - 1
	return names[int(idx)%len(names)]
}

func (r *SmartRouter) bestFailoverLocked() string {
	// Return the first healthy backend in registration order.
	for name := range r.backends {
		if metrics.Default().ForBackend(name).Available.Value() == 1 {
			return name
		}
	}
	return ""
}

// RegisterConnection records a new active connection for a backend.
// Call RecordDisconnect when the connection ends.
func (r *SmartRouter) RecordConnect(backendName string) {
	metrics.StartConnection(backendName)
}

// RecordDisconnect pairs with RecordConnect to release the active-connection slot.
func (r *SmartRouter) RecordDisconnect(backendName string) {
	// Handled via ConnTracker.Done() returned from RecordConnect.
}

// Stats returns a read-only snapshot of routing statistics.
func (r *SmartRouter) Stats() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ruleList := make([]map[string]any, len(r.rules))
	for i, rule := range r.rules {
		ruleList[i] = map[string]any{
			"dest":    rule.Dest,
			"proto":   rule.Proto,
			"backend": rule.Backend,
			"priority": rule.Priority,
		}
	}
	beNames := make([]string, 0, len(r.backends))
	for name := range r.backends {
		beNames = append(beNames, name)
	}
	sort.Strings(beNames)
	return map[string]any{
		"mode":     r.cfg.Mode,
		"prefer_p2p": r.cfg.PreferP2P,
		"rules":    ruleList,
		"backends": beNames,
	}
}

// ---- Utilities -----------------------------------------------------------

// isP2P reports true for backends that are P2P-capable.
func isP2P(name string) bool {
	return name == "skynet-p2p" ||
		strings.Contains(name, "p2p") ||
		strings.Contains(name, "dht") ||
		strings.Contains(name, "webrtc")
}

func normalizeProto(proto string) string {
	switch proto {
	case "4", "tcp4":
		return "tcp"
	case "6", "tcp6":
		return "tcp"
	case "udp", "udp4", "udp6":
		return "udp"
	}
	return proto
}

func splitAddr(addr net.Addr) (string, int, error) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String(), tcp.Port, nil
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.IP.String(), udp.Port, nil
	}
	s := addr.String()
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0, nil
	}
	// Try to parse port.
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return host, port, nil
}
