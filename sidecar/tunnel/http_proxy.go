package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// httpProxyBackend is a minimal HTTP CONNECT proxy. It listens on a local
// port and accepts CONNECT requests for arbitrary host:port targets, then
// relays traffic in both directions. It deliberately supports *only* the
// CONNECT verb — plain HTTP forwarding is out of scope because most clients
// support CONNECT for HTTPS, which is what you would tunnel over.
//
// The proxy does NOT inspect or rewrite traffic beyond the initial CONNECT
// handshake; we stay transport-agnostic so the peer can run anything from
// SSH to RDP to HTTP/2 over the same tunnel.
type httpProxyBackend struct {
	cfg Config

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	started  bool
	stopped  bool
}

func newHTTPProxyBackend(cfg Config) *httpProxyBackend {
	return &httpProxyBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

func (b *httpProxyBackend) Name() string           { return "http-proxy://" + b.cfg.Name }
func (b *httpProxyBackend) Type() string           { return TypeHTTPProxy }
func (b *httpProxyBackend) Ready() <-chan struct{} { return b.ready }

func (b *httpProxyBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}
	addr := b.cfg.ProxyListen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		b.mu.Unlock()
		return fmt.Errorf("http-proxy: %w", err)
	}
	b.listener = ln
	b.started = true
	b.mu.Unlock()

	go b.acceptLoop(ctx, ln)

	// Signal ready once we are accepting.
	b.mu.Lock()
	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	b.mu.Unlock()

	return nil
}

func (b *httpProxyBackend) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		// Check ctx cancellation once per iteration.
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Accept with a short deadline so ctx cancellation can interrupt.
		if tcpLn, ok := ln.(*net.TCPListener); ok {
			_ = tcpLn.SetDeadline(time.Now().Add(250 * time.Millisecond))
		}

		conn, err := ln.Accept()
		if err != nil {
			// Stopped or deadline timeout — both are fine.
			b.mu.Lock()
			stopped := b.stopped
			b.mu.Unlock()
			if stopped || ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Unknown accept error — back off briefly.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go b.handleConn(ctx, conn)
	}
}

func (b *httpProxyBackend) handleConn(ctx context.Context, in net.Conn) {
	defer in.Close()

	// Read the first line. Expected: "CONNECT host:port HTTP/1.1\r\n"
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 || parts[0] != "CONNECT" {
		// Not a CONNECT — reply 405 Method Not Allowed and close.
		fmt.Fprintf(in, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}

	// parts[1] is "host:port". Validate and connect.
	target := parts[1]
	dialer := net.Dialer{Timeout: 10 * time.Second}
	out, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		fmt.Fprintf(in, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer out.Close()

	// Send 200 Connection Established to the client, then bidirectionally
	// relay bytes between client and target.
	fmt.Fprintf(in, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Relay — two goroutines, one per direction. When either side closes
	// the other side is also torn down.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(in, out)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(out, in)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (b *httpProxyBackend) Stop(ctx context.Context) error {
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
	return ln.Close()
}

// ListenAddr exposes the effective bound address (useful when the OS picks
// a free port for us).
func (b *httpProxyBackend) ListenAddr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listener == nil {
		return ""
	}
	return b.listener.Addr().String()
}
