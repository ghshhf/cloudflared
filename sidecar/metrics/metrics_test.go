package metrics

import (
	"fmt"
	"math"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

func TestCounterAdd(t *testing.T) {
	var c Counter
	if c.Value() != 0 {
		t.Fatalf("initial Value = %d; want 0", c.Value())
	}
	c.Add(42)
	if c.Value() != 42 {
		t.Errorf("after Add(42), Value = %d; want 42", c.Value())
	}
	c.Add(58)
	if c.Value() != 100 {
		t.Errorf("after Add(58), Value = %d; want 100", c.Value())
	}
}

func TestCounterConcurrent(t *testing.T) {
	var c Counter
	var wg sync.WaitGroup
	n := 100
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Add(1)
		}()
	}
	wg.Wait()
	if c.Value() != uint64(n) {
		t.Errorf("concurrent add: Value = %d; want %d", c.Value(), n)
	}
}

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

func TestGaugeSetAndAdd(t *testing.T) {
	var g Gauge
	if g.Value() != 0 {
		t.Fatalf("initial Value = %d; want 0", g.Value())
	}
	g.Set(42)
	if g.Value() != 42 {
		t.Errorf("after Set(42), Value = %d; want 42", g.Value())
	}
	g.Add(10)
	if g.Value() != 52 {
		t.Errorf("after Add(10), Value = %d; want 52", g.Value())
	}
	g.Add(-20)
	if g.Value() != 32 {
		t.Errorf("after Add(-20), Value = %d; want 32", g.Value())
	}
}

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

func TestHistogramEmpty(t *testing.T) {
	h := NewHistogram(100)
	if p := h.Percentile(0.50); p != 0 {
		t.Errorf("p50 of empty histogram = %f; want 0", p)
	}
}

func TestHistogramSingleValue(t *testing.T) {
	h := NewHistogram(100)
	h.Observe(42.0)
	for _, p := range []float64{0.50, 0.75, 0.90, 0.99} {
		if v := h.Percentile(p); v != 42.0 {
			t.Errorf("p%02.f of [42] = %f; want 42", p*100, v)
		}
	}
}

func TestHistogramMultipleValues(t *testing.T) {
	h := NewHistogram(1000)
	for i := 1; i <= 100; i++ {
		h.Observe(float64(i))
	}

	// With 100 samples sorted 1..100:
	// p50 ≈ 50.5 (ceil(0.5*100)-1 = 49 → 50)
	// p90 ≈ 90.5 (ceil(0.9*100)-1 = 89 → 90)
	// p99 ≈ 99.5 (ceil(0.99*100)-1 = 98 → 99)
	tests := []struct {
		p    float64
		want float64
	}{
		{0.50, 50},
		{0.90, 90},
		{0.99, 99},
	}
	for _, tc := range tests {
		got := h.Percentile(tc.p)
		if math.Abs(got-tc.want) > 0.5 {
			t.Errorf("p%02.f = %f; want ≈%f", tc.p*100, got, tc.want)
		}
	}
}

func TestHistogramWindowSize(t *testing.T) {
	h := NewHistogram(10)
	for i := 0; i < 20; i++ {
		h.Observe(float64(i))
	}
	// Only the last 10 values are kept (10..19).
	// p50 should be in [14,15]
	p50 := h.Percentile(0.50)
	if p50 < 14 || p50 > 15 {
		t.Errorf("p50 (with sliding window) = %f; want ≈14-15", p50)
	}
}

func TestNewHistogramDefaultWindow(t *testing.T) {
	h := NewHistogram(0)
	if h.window != 1000 {
		t.Errorf("window = %d; want 1000 (default)", h.window)
	}
}

// ---------------------------------------------------------------------------
// Collector — ForBackend
// ---------------------------------------------------------------------------

func TestCollectorForBackend(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	m := c.ForBackend("test")
	if m == nil {
		t.Fatal("ForBackend returned nil")
	}
	if m.Name != "test" {
		t.Errorf("Name = %q; want test", m.Name)
	}
	if m.Available.Value() != 1 {
		t.Errorf("Available = %d; want 1 (default healthy)", m.Available.Value())
	}

	// Same name returns the same instance.
	m2 := c.ForBackend("test")
	if m != m2 {
		t.Error("ForBackend for the same name returned a different instance")
	}
}

func TestCollectorBackends(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	c.ForBackend("a")
	c.ForBackend("b")
	c.ForBackend("c")

	backends := c.Backends()
	if len(backends) != 3 {
		t.Errorf("Backends = %v; want 3", backends)
	}
	// Verify sorted.
	if !sort.StringsAreSorted(backends) {
		t.Errorf("Backends not sorted: %v", backends)
	}
}

func TestCollectorSnapshot(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	m := c.ForBackend("snap")
	m.ConnectionsActive.Set(5)
	m.BytesSentTotal.Add(1000)

	snap := c.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot size = %d; want 1", len(snap))
	}
	if snap["snap"].ConnectionsActive.Value() != 5 {
		t.Errorf("snapshot connections = %d; want 5", snap["snap"].ConnectionsActive.Value())
	}
}

func TestCollectorSnapshotIsCopy(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	m := c.ForBackend("original")
	m.BytesSentTotal.Add(100)

	snap := c.Snapshot()
	snap["original"].BytesSentTotal.Add(200)

	// Snapshot should reflect the same pointer (it's a shallow copy of the
	// BackendMetrics, not a deep copy). This documents current behavior.
	if c.ForBackend("original").BytesSentTotal.Value() != 300 {
		t.Errorf("modifying snapshot modified original = %d; want 300", c.ForBackend("original").BytesSentTotal.Value())
	}
}

// ---------------------------------------------------------------------------
// Collector — Stats
// ---------------------------------------------------------------------------

func TestCollectorStats(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	m := c.ForBackend("stats-test")
	m.ConnectionsActive.Set(3)
	m.BytesSentTotal.Add(500)
	m.BytesRecvTotal.Add(200)
	m.ErrorsTotal.Add(1)
	m.Available.Set(1)
	m.Latency.Observe(0.05)
	m.Latency.Observe(0.10)

	stats := c.Stats()
	s, ok := stats["stats-test"]
	if !ok {
		t.Fatal("stats entry not found")
	}
	if s["connections_active"].(int64) != 3 {
		t.Errorf("connections_active = %v; want 3", s["connections_active"])
	}
	if s["bytes_sent_total"].(uint64) != 500 {
		t.Errorf("bytes_sent_total = %v; want 500", s["bytes_sent_total"])
	}
	if s["available"].(bool) != true {
		t.Errorf("available = %v; want true", s["available"])
	}
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

func TestDefaultCollector(t *testing.T) {
	d := Default()
	if d == nil {
		t.Fatal("Default() returned nil")
	}
	// ForBackend on the global instance should work.
	m := d.ForBackend("global-test")
	m.BytesSentTotal.Add(10)
	if m.BytesSentTotal.Value() != 10 {
		t.Errorf("global metric value = %d; want 10", m.BytesSentTotal.Value())
	}
}

// ---------------------------------------------------------------------------
// Prometheus handler
// ---------------------------------------------------------------------------

func TestPrometheusHandler(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	m := c.ForBackend("prom-test")
	m.ConnectionsActive.Set(2)
	m.BytesSentTotal.Add(500)
	m.BytesRecvTotal.Add(300)
	m.ErrorsTotal.Add(1)
	m.Available.Set(1)

	// Replace global for this test.
	old := global
	global = c
	defer func() { global = old }()

	handler := Handler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "# HELP sidecar_connections_active") {
		t.Errorf("missing help line in metrics output")
	}
	if !strings.Contains(body, `sidecar_connections_active{backend="prom-test"} 2`) {
		t.Errorf("missing connections_active metric: %s", body)
	}
	if !strings.Contains(body, `sidecar_bytes_sent_total{backend="prom-test"} 500`) {
		t.Errorf("missing bytes_sent_total metric: %s", body)
	}
	if !strings.Contains(body, `sidecar_bytes_recv_total{backend="prom-test"} 300`) {
		t.Errorf("missing bytes_recv_total metric: %s", body)
	}
	if !strings.Contains(body, `sidecar_errors_total{backend="prom-test"} 1`) {
		t.Errorf("missing errors_total metric: %s", body)
	}
	if !strings.Contains(body, `sidecar_backend_available{backend="prom-test"} 1`) {
		t.Errorf("missing backend_available metric: %s", body)
	}
	if !strings.Contains(body, `sidecar_failovers_total{backend="prom-test"} 0`) {
		t.Errorf("missing failovers_total metric: %s", body)
	}
	if !strings.Contains(body, "sidecar_latency_p50_seconds") {
		t.Errorf("missing latency p50 metric: %s", body)
	}
}

// ---------------------------------------------------------------------------
// ConnTracker
// ---------------------------------------------------------------------------

func TestStartConnectionDone(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	old := global
	global = c
	defer func() { global = old }()

	c.ForBackend("tracker-test")

	tracker := StartConnection("tracker-test")
	if c.ForBackend("tracker-test").ConnectionsActive.Value() != 1 {
		t.Errorf("after Start, active = %d; want 1", c.ForBackend("tracker-test").ConnectionsActive.Value())
	}
	tracker.Done()
	if c.ForBackend("tracker-test").ConnectionsActive.Value() != 0 {
		t.Errorf("after Done, active = %d; want 0", c.ForBackend("tracker-test").ConnectionsActive.Value())
	}
}

// ---------------------------------------------------------------------------
// FormatBandwidth
// ---------------------------------------------------------------------------

func TestFormatBandwidth(t *testing.T) {
	tests := []struct {
		bps  float64
		want string
	}{
		{0, "0 B/s"},
		{500, "500 B/s"},
		{1023, "1023 B/s"},
		{1024, "1.00 KB/s"},
		{1536, "1.50 KB/s"},
		{1048576, "1.00 MB/s"},
		{1073741824, "1.00 GB/s"},
		{1099511627776, "1.00 TB/s"},
	}
	for _, tc := range tests {
		got := FormatBandwidth(tc.bps)
		if got != tc.want {
			t.Errorf("FormatBandwidth(%f) = %q; want %q", tc.bps, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RecordLatency, RecordError, RecordFailover, RecordTransfer, SetAvailable
// ---------------------------------------------------------------------------

func TestRecordHelpers(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	old := global
	global = c
	defer func() { global = old }()

	c.ForBackend("helper-test")

	RecordError("helper-test")
	if c.ForBackend("helper-test").ErrorsTotal.Value() != 1 {
		t.Errorf("after RecordError, errors = %d; want 1", c.ForBackend("helper-test").ErrorsTotal.Value())
	}

	RecordFailover("helper-test")
	if c.ForBackend("helper-test").FailoversTotal.Value() != 1 {
		t.Errorf("after RecordFailover, failovers = %d; want 1", c.ForBackend("helper-test").FailoversTotal.Value())
	}

	RecordTransfer("helper-test", 100, 50)
	m := c.ForBackend("helper-test")
	if m.BytesSentTotal.Value() != 100 {
		t.Errorf("after RecordTransfer(100,50), sent = %d; want 100", m.BytesSentTotal.Value())
	}
	if m.BytesRecvTotal.Value() != 50 {
		t.Errorf("after RecordTransfer(100,50), recv = %d; want 50", m.BytesRecvTotal.Value())
	}

	// Negative values should be ignored.
	RecordTransfer("helper-test", -1, -1)
	if m.BytesSentTotal.Value() != 100 {
		t.Errorf("after negative sent transfer, sent = %d; still want 100", m.BytesSentTotal.Value())
	}

	SetAvailable("helper-test", false)
	if c.ForBackend("helper-test").Available.Value() != 0 {
		t.Errorf("after SetAvailable(false), Available = %d; want 0", c.ForBackend("helper-test").Available.Value())
	}

	SetAvailable("helper-test", true)
	if c.ForBackend("helper-test").Available.Value() != 1 {
		t.Errorf("after SetAvailable(true), Available = %d; want 1", c.ForBackend("helper-test").Available.Value())
	}
}

// ---------------------------------------------------------------------------
// BestBackend
// ---------------------------------------------------------------------------

func TestBestBackendEmpty(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	old := global
	global = c
	defer func() { global = old }()

	dec := BestBackend(false)
	if dec.Backend != "" {
		t.Errorf("BestBackend on empty collector = %+v; want empty", dec)
	}
}

func TestBestBackendPicksHealthy(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	old := global
	global = c
	defer func() { global = old }()

	// 2 backends: one healthy, one unhealthy.
	a := c.ForBackend("slow")
	a.Available.Set(1)
	a.Latency.Observe(0.5)

	b := c.ForBackend("fast")
	b.Available.Set(1)
	b.Latency.Observe(0.01)

	dec := BestBackend(false)
	if dec.Backend != "fast" {
		t.Errorf("BestBackend picked %q; want 'fast'", dec.Backend)
	}
	if dec.Reason != "lowest_latency" {
		t.Errorf("Reason = %q; want 'lowest_latency'", dec.Reason)
	}
}

func TestBestBackendSkipsUnhealthy(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	old := global
	global = c
	defer func() { global = old }()

	a := c.ForBackend("unhealthy")
	a.Available.Set(0)

	b := c.ForBackend("healthy")
	b.Available.Set(1)
	b.Latency.Observe(0.1)

	dec := BestBackend(false)
	if dec.Backend != "healthy" {
		t.Errorf("BestBackend picked %q; want 'healthy'", dec.Backend)
	}
}

func TestBestBackendPrefersP2P(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	old := global
	global = c
	defer func() { global = old }()

	a := c.ForBackend("tcp-relay")
	a.Available.Set(1)
	a.Latency.Observe(0.01)

	b := c.ForBackend("skynet-p2p")
	b.Available.Set(1)
	b.Latency.Observe(0.5)

	dec := BestBackend(true)
	if dec.Backend != "skynet-p2p" {
		t.Errorf("BestBackend(preferP2P) picked %q; want 'skynet-p2p'", dec.Backend)
	}
	if dec.Reason != "prefer_p2p" {
		t.Errorf("Reason = %q; want 'prefer_p2p'", dec.Reason)
	}
}

// ---------------------------------------------------------------------------
// Histogram — concurrent reads and writes
// ---------------------------------------------------------------------------

func TestHistogramConcurrent(t *testing.T) {
	h := NewHistogram(1000)
	var wg sync.WaitGroup

	// 10 concurrent writers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				h.Observe(float64(j))
			}
		}()
	}
	// 5 concurrent readers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = h.Percentile(0.50)
				_ = h.Percentile(0.99)
			}
		}()
	}
	wg.Wait()
	// After concurrent ops, p50 should be meaningful.
	p50 := h.Percentile(0.50)
	if p50 < 0 || p50 > 100 {
		t.Errorf("p50 after concurrent ops = %f; want in [0,100]", p50)
	}
}

// ---------------------------------------------------------------------------
// Collector — concurrent ForBackend
// ---------------------------------------------------------------------------

func TestCollectorConcurrentForBackend(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := fmt.Sprintf("backend-%d", n)
			m := c.ForBackend(name)
			m.BytesSentTotal.Add(uint64(n))
		}(i)
	}
	wg.Wait()
	backends := c.Backends()
	if len(backends) != 20 {
		t.Errorf("Backends = %d; want 20", len(backends))
	}
}

// ---------------------------------------------------------------------------
// Snapshot — concurrent access safe
// ---------------------------------------------------------------------------

func TestSnapshotWhileUpdating(t *testing.T) {
	c := &Collector{backends: make(map[string]*BackendMetrics)}
	done := make(chan struct{})
	defer close(done)

	// Background writer.
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				m := c.ForBackend("concurrent")
				m.BytesSentTotal.Add(1)
			}
		}
	}()

	// Read snapshots concurrently.
	for i := 0; i < 50; i++ {
		snap := c.Snapshot()
		if len(snap) > 0 {
			if m, ok := snap["concurrent"]; ok {
				_ = m.BytesSentTotal.Value()
			}
		}
	}
}

