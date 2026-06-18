// Package tunnel provides pluggable tunnel transport backends.
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

// quicBackend is a QUIC-based tunnel backend.
// QUIC (RFC 9000) provides:
//   - 0-RTT connection establishment (no handshake latency after first connection)
//   - Built-in TLS 1.3 encryption (mandatory)
//   - Stream multiplexing (multiple logical channels over one connection)
//   - Better handling of packet loss (only affected streams, not the whole connection)
//   - Congestion control built-in
//
// QUIC uses UDP as its underlying transport, making it firewall-friendly
// (most firewalls allow UDP/443 out).
//
// This stub implements the tunnel.Backend interface and provides the
// connection structure. Replace with a full QUIC library (e.g. quic-go)
// for production use.
type quicBackend struct {
	cfg Config

	mu      sync.Mutex
	conn    net.Conn
	ready   chan struct{}
	started bool
	stopped bool

	// QUIC-specific settings.
	quicAddr    string // QUIC server address
	connLatency int64  // last measured RTT in ms
}

// newQUICBackend creates a new QUIC-backed tunnel.
func newQUICBackend(cfg Config) *quicBackend {
	return &quicBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

func (b *quicBackend) Name() string           { return "quic://" + b.cfg.Name }
func (b *quicBackend) Type() string           { return "quic" }
func (b *quicBackend) Ready() <-chan struct{} { return b.ready }

func (b *quicBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	b.quicAddr = b.cfg.RelayTarget
	if b.quicAddr == "" {
		b.quicAddr = b.cfg.OriginURL
	}
	if b.quicAddr == "" {
		b.mu.Unlock()
		return fmt.Errorf("quic: empty relay_target; set quic server address")
	}

	// For the stub: connect via UDP (QUIC runs over UDP).
	// A production implementation would use a QUIC library here.
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", b.quicAddr)
	if err != nil {
		b.mu.Unlock()
		metrics.SetAvailable("quic", false)
		return quicBackendError("quic: dial "+b.quicAddr, err)
	}

	b.conn = conn
	b.started = true
	b.mu.Unlock()

	metrics.SetAvailable("quic", true)
	go b.measureLatency()

	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	return nil
}

// measureLatency periodically measures RTT to the QUIC server.
func (b *quicBackend) measureLatency() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if b.conn == nil {
			return
		}
		ticker.Stop()
		ticker = time.NewTicker(5 * time.Second)
		start := time.Now()
		// Write a 1-byte keepalive probe.
		b.mu.Lock()
		conn := b.conn
		b.mu.Unlock()
		if conn == nil {
			return
		}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Write([]byte{0x0D}) // QUIC PING frame (simplified)
		if err != nil {
			metrics.RecordError("quic")
			continue
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		rtt := time.Since(start).Seconds()
		atomic.StoreInt64(&b.connLatency, int64(rtt*1000))
		metrics.Default().ForBackend("quic").Latency.Observe(rtt)
	}
}

func quicBackendError(msg string, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return fmt.Errorf("%s", msg)
}

func (b *quicBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{})
	metrics.SetAvailable("quic", false)
	return nil
}
