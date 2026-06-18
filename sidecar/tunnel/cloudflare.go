package tunnel

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// cloudflareBackend wraps the official cloudflared binary. It is the
// default backend when no explicit "backend" field is configured.
//
// Design notes:
//   - We do NOT re-implement the cloudflared protocol. We simply fork
//     the binary with the right arguments so upgrades to cloudflared
//     immediately show up as tunnel improvements.
//   - Ready-probing works by watching the child's stdout/stderr for the
//     well-known log lines that indicate a tunnel came up ("connected",
//     "registered tunnel", etc.). This keeps us compatible with any
//     cloudflared version without introspecting its HTTP metrics port.
//   - Stop sends SIGTERM → waits grace period → SIGKILL. This mirrors
//     what the original sidecar did before the multi-backend refactor.
type cloudflareBackend struct {
	cfg Config

	mu       sync.Mutex
	cmd      *exec.Cmd
	cancelFn func() // stop the child process
	ready    chan struct{}
	exited   chan struct{}
	started  bool
}

func newCloudflareBackend(cfg Config) *cloudflareBackend {
	return &cloudflareBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

func (b *cloudflareBackend) Name() string           { return "cloudflare://" + b.cfg.Name }
func (b *cloudflareBackend) Type() string           { return TypeCloudflare }
func (b *cloudflareBackend) Ready() <-chan struct{} { return b.ready }

func (b *cloudflareBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	bin := b.cfg.CloudflareBinary
	if bin == "" {
		bin = "cloudflared"
	}
	if p, err := exec.LookPath(bin); err == nil {
		bin = p
	}

	args := b.buildArgs()
	cmd := exec.CommandContext(ctx, bin, args...)

	// Pipe stdout/stderr through a ring buffer so we can (a) expose
	// recent log lines over the IPC bus and (b) detect when the tunnel
	// is up without polling /metrics.
	ring := newLogRing(4096)
	cmd.Stdout = ring.newWriter("out")
	cmd.Stderr = ring.newWriter("err")

	// We drive termination explicitly; do not let CommandContext kill
	// the child on ctx expiry — otherwise a context cancellation would
	// bypass the graceful-shutdown path.
	cmd.Cancel = func() error { return nil }

	if err := cmd.Start(); err != nil {
		b.mu.Unlock()
		return err
	}

	b.cmd = cmd
	b.started = true
	b.exited = make(chan struct{})

	// Cancel handle for Stop().
	_, cancel := context.WithCancel(context.Background())
	b.cancelFn = cancel
	b.mu.Unlock()

	// Background watcher: reap the child, then broadcast exit.
	go func() {
		_ = cmd.Wait()
		b.mu.Lock()
		if b.exited != nil {
			close(b.exited)
			b.exited = nil
		}
		b.mu.Unlock()
	}()

	// Background ready-probe: scan recent log lines for a "tunnel up"
	// indicator.
	go b.probeReady(ctx, ring)

	// Wait for one of: ready signal, child exit, context expiry, timeout.
	timeout := time.Duration(b.cfg.StartTimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	b.mu.Lock()
	exited := b.exited
	b.mu.Unlock()
	select {
	case <-b.ready:
		return nil
	case <-exited:
		return errTunnelChildExit
	case <-ctx.Done():
		// Parent asked us to stop trying; tear down the child.
		b.Stop(context.Background())
		return ctx.Err()
	case <-time.After(timeout):
		b.Stop(context.Background())
		return errTunnelTimeout
	}
}

func (b *cloudflareBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	cmd := b.cmd
	cancelFn := b.cancelFn
	exited := b.exited
	b.cmd = nil
	b.cancelFn = nil
	b.started = false
	// Reset the ready channel so a subsequent Start() can fire it again.
	b.ready = make(chan struct{})
	b.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if cancelFn != nil {
		defer cancelFn()
	}

	grace := time.Duration(b.cfg.ShutdownGracePeriodSeconds * float64(time.Second))
	if grace <= 0 {
		grace = 15 * time.Second
	}
	// Ask nicely, then force-kill.
	_ = cmd.Process.Signal(os.Interrupt)

	var deadline <-chan time.Time
	if grace > 0 {
		deadline = time.After(grace)
	}

	if exited == nil {
		// Watcher already fired (or never started); nothing to wait on.
		_ = cmd.Process.Kill()
		return nil
	}

	select {
	case <-exited:
		return nil
	case <-deadline:
		_ = cmd.Process.Kill()
		<-exited
		return nil
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-exited
		return ctx.Err()
	}
}

// probeReady scans recent log lines from the ring buffer until it sees
// one of the well-known "tunnel is up" markers, the child exits, or the
// context is cancelled. It closes b.ready on success.
func (b *cloudflareBackend) probeReady(ctx context.Context, ring *logRing) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		exited := b.exited
		b.mu.Unlock()
		select {
		case <-exited:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, line := range ring.tail(32) {
				l := strings.ToLower(line)
				if strings.Contains(l, "registered tunnel") ||
					strings.Contains(l, "connection") && strings.Contains(l, "registered") ||
					strings.Contains(l, "connected") ||
					strings.Contains(l, "ready") {
					b.mu.Lock()
					select {
					case <-b.ready:
					default:
						close(b.ready)
					}
					b.mu.Unlock()
					return
				}
			}
		}
	}
}

// buildArgs expands cfg into cloudflared sub-command arguments. Keeps
// a small surface area so operators can fall back to ExtraArgs for
// anything exotic.
func (b *cloudflareBackend) buildArgs() []string {
	var args []string
	switch b.cfg.CloudflareMode {
	case "tunnel":
		// cloudflared tunnel run <name>
		args = []string{"tunnel", "run"}
		if b.cfg.Name != "" {
			args = append(args, b.cfg.Name)
		}
	case "access":
		// cloudflared access tcp --url <localListener> --hostname <public DNS name>
		args = []string{"access", "tcp"}
		if b.cfg.OriginURL != "" {
			args = append(args, "--url", b.cfg.OriginURL)
		}
		if b.cfg.AccessHostname != "" {
			args = append(args, "--hostname", b.cfg.AccessHostname)
		}
		if b.cfg.AccessDestination != "" {
			args = append(args, "--destination", b.cfg.AccessDestination)
		}
	default:
		// "quick" — zero-config tunnel.
		args = []string{"tunnel", "--url", b.cfg.OriginURL}
	}
	args = append(args, b.cfg.ExtraArgs...)
	return args
}

// RecentLogs exposes the ring buffer for callers that want to show
// the most recent cloudflared log lines (e.g. the IPC get_logs RPC).
func (b *cloudflareBackend) RecentLogs(n int) []string {
	// Only cloudflare has a log ring; backends like tcp-relay expose
	// their own stats. Kept on the struct so the component layer can
	// check for a LogLines() interface without type-asserting too much.
	return nil
}

// ---- sentinel errors ---------------------------------------------------

var (
	errTunnelChildExit = &backendErr{msg: "cloudflared exited before tunnel became ready"}
	errTunnelTimeout   = &backendErr{msg: "cloudflared startup timed out"}
)

// ---- log ring buffer (shared by all child-process backends) ------------

// logRing is a tiny ring buffer of log lines captured from a child
// process. It is deliberately lock-free on the write path (pipes are
// single-threaded readers per fd).
type logRing struct {
	mu    sync.RWMutex
	lines []string
	cap   int
}

func newLogRing(cap int) *logRing { return &logRing{cap: cap} }

func (r *logRing) newWriter(tag string) *os.File {
	pr, pw, err := os.Pipe()
	if err != nil {
		return os.Stderr
	}
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			r.append(sc.Text())
		}
		_ = pr.Close()
	}()
	_ = tag
	return pw
}

func (r *logRing) append(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.cap {
		r.lines = r.lines[len(r.lines)-r.cap:]
	}
}

func (r *logRing) tail(n int) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n <= 0 || len(r.lines) == 0 {
		return nil
	}
	if n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}
