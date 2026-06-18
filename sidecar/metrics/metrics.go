// Package metrics provides a lightweight, Prometheus-compatible observability
// layer for the cloudflared sidecar. It has zero external dependencies.
//
// Counters, Gauges and Histograms are thread-safe via atomic operations.
// Each metric is keyed by backend name so every tunnel pathway is independently
// observable.
//
// Metrics exposed via GET /metrics (Prometheus text format):
//
//	# HELP sidecar_connections_active   Currently open connections per backend.
//	# TYPE sidecar_connections_active gauge
//	sidecar_connections_active{backend="cloudflare"} 3
//
//	# HELP sidecar_bytes_sent_total     Cumulative bytes sent per backend.
//	# TYPE sidecar_bytes_sent_total counter
//	sidecar_bytes_sent_total{backend="cloudflare"} 102400
//
//	# HELP sidecar_latency_seconds      Backend round-trip latency.
//	# TYPE sidecar_latency_seconds histogram
//	sidecar_latency_seconds_bucket{backend="cloudflare",le="0.1"} 20
//
// Metrics are also queryable in-process via Collector.Stats() for use by the
// embedded dashboard or any internal routing logic.
package metrics

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---- Metric types -------------------------------------------------------

// Counter is a 64-bit unsigned counter with atomic increments.
type Counter uint64

func (c *Counter) Add(delta uint64) { atomic.AddUint64((*uint64)(c), delta) }
func (c *Counter) Value() uint64    { return atomic.LoadUint64((*uint64)(c)) }

// Gauge is a 64-bit signed gauge with atomic store/inc/dec.
type Gauge int64

func (g *Gauge) Set(v int64)     { atomic.StoreInt64((*int64)(g), v) }
func (g *Gauge) Add(delta int64) { atomic.AddInt64((*int64)(g), delta) }
func (g *Gauge) Value() int64    { return atomic.LoadInt64((*int64)(g)) }

// Histogram maintains a sliding window of samples and computes approximate
// percentiles (p50, p75, p90, p99) without external dependencies.
type Histogram struct {
	mu      sync.Mutex
	samples []float64
	window  int
}

// NewHistogram creates a histogram with the specified sliding window size.
func NewHistogram(window int) *Histogram {
	if window <= 0 {
		window = 1000
	}
	return &Histogram{samples: make([]float64, 0, window), window: window}
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = append(h.samples, v)
	if len(h.samples) > h.window {
		copy(h.samples, h.samples[1:])
		h.samples = h.samples[:len(h.samples)-1]
	}
}

func (h *Histogram) Percentile(p float64) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.samples) == 0 {
		return 0
	}
	sorted := make([]float64, len(h.samples))
	copy(sorted, h.samples)
	sort.Float64s(sorted)
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

// ---- Backend metrics -----------------------------------------------------

// BackendMetrics holds all metrics for a single backend path.
type BackendMetrics struct {
	Name string // e.g. "cloudflare", "tcp-relay", "failover-cloudflare"

	ConnectionsActive Gauge // currently open connections
	BytesSentTotal    Counter
	BytesRecvTotal    Counter
	ErrorsTotal       Counter // connection errors, write/read failures
	FailoversTotal    Counter // times this backend caused/handled a failover
	Latency           *Histogram

	// Availability: 1 = healthy, 0 = unhealthy
	Available Gauge

	// Timestamps
	LastErrorAt    int64 // unix nano, 0 if no error
	LastFailoverAt int64
}

// ---- Global collector ----------------------------------------------------

// Collector is the singleton registry that holds per-backend metrics.
// It is safe for concurrent use.
type Collector struct {
	mu       sync.RWMutex
	backends map[string]*BackendMetrics
}

var global = &Collector{backends: make(map[string]*BackendMetrics)}

// Default returns the global collector.
func Default() *Collector { return global }

// ForBackend returns (creating if needed) the metrics for the named backend.
func (c *Collector) ForBackend(name string) *BackendMetrics {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m, ok := c.backends[name]; ok {
		return m
	}
	m := &BackendMetrics{
		Name:      name,
		Latency:   NewHistogram(200),
		Available: Gauge(1),
	}
	c.backends[name] = m
	return m
}

// Backends returns a snapshot of all registered backend names.
func (c *Collector) Backends() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.backends))
	for n := range c.backends {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Snapshot returns a read-only copy of all backend metrics.
// Use for /metrics endpoint and dashboard.
func (c *Collector) Snapshot() map[string]*BackendMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]*BackendMetrics, len(c.backends))
	for k, v := range c.backends {
		out[k] = v
	}
	return out
}

// Stats returns a lightweight summary map for dashboard / internal routing.
func (c *Collector) Stats() map[string]map[string]any {
	snap := c.Snapshot()
	out := make(map[string]map[string]any)
	for name, m := range snap {
		out[name] = map[string]any{
			"connections_active": m.ConnectionsActive.Value(),
			"bytes_sent_total":   m.BytesSentTotal.Value(),
			"bytes_recv_total":   m.BytesRecvTotal.Value(),
			"errors_total":       m.ErrorsTotal.Value(),
			"failovers_total":    m.FailoversTotal.Value(),
			"available":          m.Available.Value() == 1,
			"latency_p50_ms":     math.Round(m.Latency.Percentile(0.50)*1000) / 1000,
			"latency_p90_ms":     math.Round(m.Latency.Percentile(0.90)*1000) / 1000,
			"latency_p99_ms":     math.Round(m.Latency.Percentile(0.99)*1000) / 1000,
		}
	}
	return out
}

// ---- Prometheus exposition handler ----------------------------------------

// Handler returns an http.Handler that renders all metrics in Prometheus
// text format. Attach with:
//   mux.Handle("/metrics", metrics.Handler())
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		snap := global.Snapshot()

		// Sidecar connection metrics
		fmt.Fprintln(w, "# HELP sidecar_connections_active Currently open connections per backend.")
		fmt.Fprintln(w, "# TYPE sidecar_connections_active gauge")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_connections_active{backend=%q} %d\n",
				m.Name, m.ConnectionsActive.Value())
		}

		// Bytes sent
		fmt.Fprintln(w, "# HELP sidecar_bytes_sent_total Cumulative bytes sent per backend.")
		fmt.Fprintln(w, "# TYPE sidecar_bytes_sent_total counter")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_bytes_sent_total{backend=%q} %d\n",
				m.Name, m.BytesSentTotal.Value())
		}

		// Bytes received
		fmt.Fprintln(w, "# HELP sidecar_bytes_recv_total Cumulative bytes received per backend.")
		fmt.Fprintln(w, "# TYPE sidecar_bytes_recv_total counter")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_bytes_recv_total{backend=%q} %d\n",
				m.Name, m.BytesRecvTotal.Value())
		}

		// Errors
		fmt.Fprintln(w, "# HELP sidecar_errors_total Total errors per backend.")
		fmt.Fprintln(w, "# TYPE sidecar_errors_total counter")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_errors_total{backend=%q} %d\n",
				m.Name, m.ErrorsTotal.Value())
		}

		// Failovers
		fmt.Fprintln(w, "# HELP sidecar_failovers_total Total failover events per backend.")
		fmt.Fprintln(w, "# TYPE sidecar_failovers_total counter")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_failovers_total{backend=%q} %d\n",
				m.Name, m.FailoversTotal.Value())
		}

		// Availability
		fmt.Fprintln(w, "# HELP sidecar_backend_available 1 if backend is healthy, 0 otherwise.")
		fmt.Fprintln(w, "# TYPE sidecar_backend_available gauge")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_backend_available{backend=%q} %d\n",
				m.Name, m.Available.Value())
		}

		// Latency percentiles (as gauges, simpler than histograms for small cardinality)
		fmt.Fprintln(w, "# HELP sidecar_latency_p50_seconds P50 round-trip latency.")
		fmt.Fprintln(w, "# TYPE sidecar_latency_p50_seconds gauge")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_latency_p50_seconds{backend=%q} %.6f\n",
				m.Name, m.Latency.Percentile(0.50))
		}
		fmt.Fprintln(w, "# HELP sidecar_latency_p99_seconds P99 round-trip latency.")
		fmt.Fprintln(w, "# TYPE sidecar_latency_p99_seconds gauge")
		for _, m := range sortedMetrics(snap) {
			fmt.Fprintf(w, "sidecar_latency_p99_seconds{backend=%q} %.6f\n",
				m.Name, m.Latency.Percentile(0.99))
		}
	})
}

func sortedMetrics(snap map[string]*BackendMetrics) []*BackendMetrics {
	names := make([]string, 0, len(snap))
	for n := range snap {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*BackendMetrics, len(names))
	for i, n := range names {
		out[i] = snap[n]
	}
	return out
}

// ---- Convenience helpers used by tunnel backends -----------------------

// RecordLatency measures the duration of fn and records it as a latency sample
// for the named backend.
func RecordLatency(backendName string, fn func() error) error {
	start := time.Now()
	err := fn()
	if err == nil {
		Default().ForBackend(backendName).Latency.Observe(time.Since(start).Seconds())
	}
	return err
}

// RecordTransfer records bytes sent and received for the named backend.
// Pass negative values for recvBytes if only sentBytes is known.
func RecordTransfer(backendName string, sentBytes, recvBytes int64) {
	m := Default().ForBackend(backendName)
	if sentBytes > 0 {
		m.BytesSentTotal.Add(uint64(sentBytes))
	}
	if recvBytes > 0 {
		m.BytesRecvTotal.Add(uint64(recvBytes))
	}
}

// RecordError increments the error counter and sets LastErrorAt for the named backend.
func RecordError(backendName string) {
	m := Default().ForBackend(backendName)
	m.ErrorsTotal.Add(1)
	atomic.StoreInt64(&m.LastErrorAt, time.Now().UnixNano())
}

// RecordFailover increments the failover counter and sets LastFailoverAt.
func RecordFailover(backendName string) {
	m := Default().ForBackend(backendName)
	m.FailoversTotal.Add(1)
	atomic.StoreInt64(&m.LastFailoverAt, time.Now().UnixNano())
}

// SetAvailable sets the backend availability flag (1=up, 0=down).
func SetAvailable(backendName string, up bool) {
	m := Default().ForBackend(backendName)
	if up {
		m.Available.Set(1)
	} else {
		m.Available.Set(0)
	}
}

// ConnTracker is a tiny helper that increments/decrements the active-connection
// gauge automatically when a connection is opened/closed.
// Usage:
//
//	tracker := metrics.StartConnection("cloudflare")
//	// do work ...
//	tracker.Done()
type ConnTracker struct {
	name  string
	gauge *Gauge
}

func StartConnection(backendName string) *ConnTracker {
	m := Default().ForBackend(backendName)
	m.ConnectionsActive.Add(1)
	return &ConnTracker{name: backendName, gauge: &m.ConnectionsActive}
}

func (c *ConnTracker) Done() { c.gauge.Add(-1) }

// FormatBandwidth formats bytes-per-second as a human-readable string.
func FormatBandwidth(bytesPerSec float64) string {
	const unit = 1024.0
	if bytesPerSec < unit {
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
	denom := unit
	units := []string{"KB/s", "MB/s", "GB/s", "TB/s"}
	for _, u := range units {
		denom *= unit
		if bytesPerSec < denom {
			return fmt.Sprintf("%.2f %s", bytesPerSec/(denom/unit), u)
		}
	}
	return fmt.Sprintf("%.2f TB/s", bytesPerSec/(denom/unit))
}

// ---- Routing helpers (used by Smart Router) -----------------------------

// RoutingDecision is the result of the routing algorithm — which backend
// to use and why.
type RoutingDecision struct {
	Backend    string
	Reason     string // human-readable: "lowest_latency", "only_healthy", "prefer_p2p"
	LatencyP99 float64
	Available  bool
}

// BestBackend returns the best available backend based on a simple weighted
// score: prefer lowest latency, but only consider backends that are healthy.
func BestBackend(preferP2P bool) RoutingDecision {
	snap := Default().Snapshot()
	if len(snap) == 0 {
		return RoutingDecision{}
	}

	type candidate struct {
		name    string
		latency float64
		avail   bool
		isP2P   bool
	}
	var candidates []candidate
	for name, m := range snap {
		if m.Available.Value() != 1 {
			continue
		}
		candidates = append(candidates, candidate{
			name:    name,
			latency: m.Latency.Percentile(0.99),
			avail:   true,
			isP2P:   strings.Contains(name, "p2p") || strings.Contains(name, "skynet"),
		})
	}

	if len(candidates) == 0 {
		return RoutingDecision{}
	}

	// Prefer P2P backends if available and preferP2P is set.
	if preferP2P {
		for _, c := range candidates {
			if c.isP2P {
				return RoutingDecision{
					Backend:    c.name,
					Reason:     "prefer_p2p",
					LatencyP99: c.latency,
					Available:  true,
				}
			}
		}
	}

	// Otherwise pick lowest P99 latency.
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.latency < best.latency {
			best = c
		}
	}
	return RoutingDecision{
		Backend:    best.name,
		Reason:     "lowest_latency",
		LatencyP99: best.latency,
		Available:  true,
	}
}
