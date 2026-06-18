package tunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// tcpRelayBackend implements a "poor man's self-hosted tunnel": it
// listens on cfg.ListenAddress and forwards every accepted TCP
// connection to cfg.RelayTarget (or cfg.OriginURL as a fallback).
//
// This is the simplest possible backend — no protocol, no third-party
// dependencies, no state other than the goroutines it launches per
// connection. Its primary purpose is (a) to prove the multi-backend
// architecture works end-to-end and (b) to let developers quickly set
// up a self-hosted tunnel on a VPS without installing anything.
type tcpRelayBackend struct {
	cfg Config

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	started  bool
	stopped  bool

	// Counters exposed via the IPC bus later.
	connCount  uint64
	activeConn int32
}

func newTCPRelayBackend(cfg Config) *tcpRelayBackend {
	return &tcpRelayBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

func (b *tcpRelayBackend) Name() string           { return "tcp-relay://" + b.cfg.Name }
func (b *tcpRelayBackend) Type() string           { return TypeTCPRelay }
func (b *tcpRelayBackend) Ready() <-chan struct{} { return b.ready }

func (b *tcpRelayBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	target := b.cfg.RelayTarget
	if target == "" {
		target = b.cfg.OriginURL
	}
	if target == "" {
		b.mu.Unlock()
		return &backendErr{msg: "tcp-relay: empty target; set origin_url or relay_target"}
	}

	listenAddr := b.cfg.ListenAddress
	if listenAddr == "" {
		listenAddr = "0.0.0.0:0" // OS picks a free port
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		b.mu.Unlock()
		metrics.SetAvailable(TypeTCPRelay, false)
		return err
	}
	metrics.SetAvailable(TypeTCPRelay, true)
	b.listener = ln
	b.started = true
	b.mu.Unlock()

	// Fire a goroutine to accept connections. Per-connection errors are
	// swallowed — we do not tear the entire backend down because one
	// client misbehaved.
	go b.acceptLoop(ctx, ln, target)

	// Signal "ready" immediately — the listener is accepting.
	b.mu.Lock()
	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	b.mu.Unlock()

	return nil
}

// acceptLoop runs until ctx or the listener is closed.
func (b *tcpRelayBackend) acceptLoop(ctx context.Context, ln net.Listener, target string) {
	for {
		// Respect context cancellation on each iteration.
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set a short accept deadline so the loop can check ctx every
		// 250ms even when Accept() otherwise blocks forever.
		tcpLn, ok := ln.(*net.TCPListener)
		if ok {
			_ = tcpLn.SetDeadline(time.Now().Add(250 * time.Millisecond))
		}

		conn, err := ln.Accept()
		if err != nil {
			b.mu.Lock()
			stopped := b.stopped
			b.mu.Unlock()
			if stopped || ctx.Err() != nil {
				return
			}
			// Back-off briefly to avoid CPU spinning on a persistent
			// accept error.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		atomic.AddUint64(&b.connCount, 1)
		atomic.AddInt32(&b.activeConn, 1)
		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				atomic.AddInt32(&b.activeConn, -1)
			}()
			b.handleConn(ctx, c, target)
		}(conn)
	}
}

// handleConn opens a TCP connection to the target and bidirectionally
// copies data between the two endpoints until either side closes.
func (b *tcpRelayBackend) handleConn(ctx context.Context, in net.Conn, target string) {
	dialer := net.Dialer{Timeout: 5 * time.Second}

	var sent, recv int64
	err := metrics.RecordLatency(TypeTCPRelay, func() error {
		out, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			return err
		}
		defer out.Close()

		// Two goroutines for bidirectional copy. Using a channel so we can
		// return as soon as either side EOFs.
		var wg sync.WaitGroup
		var sentCopy, recvCopy int64
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, _ := io.Copy(out, in)
			atomic.AddInt64(&sentCopy, n)
		}()
		go func() {
			defer wg.Done()
			n, _ := io.Copy(in, out)
			atomic.AddInt64(&recvCopy, n)
		}()
		wg.Wait()
		atomic.AddInt64(&sent, sentCopy)
		atomic.AddInt64(&recv, recvCopy)
		return nil
	})

	if err != nil {
		metrics.RecordError(TypeTCPRelay)
		return
	}
	metrics.RecordTransfer(TypeTCPRelay, sent, recv)
}

func (b *tcpRelayBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	ln := b.listener
	b.listener = nil
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{}) // reset for next Start()
	b.mu.Unlock()

	if ln == nil {
		return nil
	}
	metrics.SetAvailable(TypeTCPRelay, false)
	return ln.Close()
}

// Stats exposes counters for external observers (metrics, IPC bus, …).
// Exposed via the optional logRing-style interface in component.go.
func (b *tcpRelayBackend) Stats() (total uint64, active int32) {
	return atomic.LoadUint64(&b.connCount), atomic.LoadInt32(&b.activeConn)
}

// ListenAddr returns the effective listen address after Start() has
// succeeded. Useful when the OS picked a free port (listen on ":0").
func (b *tcpRelayBackend) ListenAddr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listener == nil {
		return ""
	}
	return b.listener.Addr().String()
}
