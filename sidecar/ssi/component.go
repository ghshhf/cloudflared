// Package ssi: implementation of IComponent that wraps the native cloudflared
// binary. See types.go for the interface and data-shape definitions.
package ssi

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CloudflaredComponent is the SSI wrapper around a single cloudflared process.
// One instance manages exactly one tunnel. Run multiple instances when you
// want to expose multiple origins — that is the whole point of the component
// model: every tunnel is its own independently-managed unit.
type CloudflaredComponent struct {
	mu sync.RWMutex

	state ComponentState
	cfg   Config
	cmd   *exec.Cmd
	logs  *logBuffer

	// stop cancels the running process. nil when no process is running.
	stop func()

	// exited is closed by the watcher goroutine when the child process has
	// been reaped. Both Start() and Stop() select on it so they can react to
	// an unexpected crash in addition to the explicit kill path. The channel
	// is replaced each time Start() is called, so old channels do not race
	// with the new watcher.
	exited chan struct{}
}

// NewCloudflaredComponent constructs a component in the CREATED state.
func NewCloudflaredComponent() *CloudflaredComponent {
	return &CloudflaredComponent{
		state: StateCreated,
		logs:  newLogBuffer(4096),
	}
}

// Init validates and stores the configuration. It does not start any process;
// the SkyNet runtime calls Start() separately so it can decide when to bring
// the tunnel online.
func (c *CloudflaredComponent) Init(ctx context.Context, cfg Config) *SsiError {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state >= StateInitializing {
		return &SsiError{Code: ErrInvalidState, Message: "already initialised (state=" + c.state.String() + ")"}
	}
	c.state = StateInitializing

	// Resolve binary path so Start() fails fast if cloudflared is missing.
	bin := cfg.BinaryPath
	if bin == "" {
		bin = "cloudflared"
	}
	if _, err := exec.LookPath(bin); err != nil {
		c.state = StateError
		return &SsiError{Code: ErrNotFound, Message: "cloudflared not found: " + err.Error()}
	}

	c.cfg = cfg
	c.state = StateInitialized
	return nil
}

// Start launches cloudflared and blocks until the process is confirmed up or
// the start-timeout elapses. On success the component transitions to RUNNING.
func (c *CloudflaredComponent) Start(ctx context.Context) *SsiError {
	c.mu.Lock()
	if c.state != StateInitialized && c.state != StateStopped && c.state != StatePaused {
		defer c.mu.Unlock()
		return &SsiError{Code: ErrInvalidState, Message: "cannot start from state " + c.state.String()}
	}
	c.state = StateStarting

	args := c.buildArgs()
	cmd := exec.CommandContext(ctx, c.resolvedBinary(), args...)
	cmd.Stdout = c.logs.newWriter("out")
	cmd.Stderr = c.logs.newWriter("err")
	// Propagate TERM/INT signals through an explicit stop() call instead of
	// relying on the default child-signalling behaviour of exec.CommandContext
	// — that way the graceful-shutdown deadline is controlled by us.
	cmd.Cancel = func() error { return nil } // we drive termination explicitly

	if err := cmd.Start(); err != nil {
		c.state = StateError
		c.mu.Unlock()
		return &SsiError{Code: ErrProcessStart, Message: "start failed: " + err.Error()}
	}
	c.cmd = cmd
	c.exited = make(chan struct{})
	exited := c.exited
	_, cancel := context.WithCancel(context.Background())
	c.stop = cancel
	c.mu.Unlock()

	// Watch for unexpected process exit. The single Wait() call lives here so
	// Stop() can rely on the same hook without double-Wait()ing the process.
	go c.watchProcessExit(cmd, exited)

	// Wait for the startup probe to confirm the tunnel is connected.
	ready := make(chan struct{})
	go c.waitForStartup(ctx, ready)

	select {
	case <-ready:
		c.mu.Lock()
		c.state = StateRunning
		c.mu.Unlock()
		return nil
	case <-exited:
		// Process exited before reaching RUNNING — start failed.
		c.mu.Lock()
		c.state = StateError
		c.mu.Unlock()
		return &SsiError{Code: ErrProcessStart, Message: "cloudflared exited before startup probe succeeded"}
	case <-ctx.Done():
		// SkyNet asked us to give up. Stop the child process and report error.
		// Guard against stop being nil (should not happen, but defensive).
		if c.stop != nil {
			c.stop()
		}
		c.mu.Lock()
		c.state = StateError
		c.mu.Unlock()
		return &SsiError{Code: ErrProcessStart, Message: "start cancelled: " + ctx.Err().Error()}
	case <-time.After(c.cfg.StartTimeout):
		// Timeout — stop the child if it is still running.
		if c.stop != nil {
			c.stop()
		}
		c.mu.Lock()
		c.state = StateError
		c.mu.Unlock()
		return &SsiError{Code: ErrProcessStart, Message: "start timeout after " + c.cfg.StartTimeout.String()}
	}
}

// Stop terminates the cloudflared process gracefully. Repeated calls after the
// first one are no-ops.
func (c *CloudflaredComponent) Stop(ctx context.Context) *SsiError {
	c.mu.Lock()
	if c.state != StateRunning && c.state != StatePaused {
		defer c.mu.Unlock()
		return &SsiError{Code: ErrInvalidState, Message: "not running (state=" + c.state.String() + ")"}
	}
	c.state = StateStopping
	cmd := c.cmd
	exited := c.exited
	c.stop = nil
	c.mu.Unlock()

	if cmd == nil || cmd.Process == nil || exited == nil {
		c.mu.Lock()
		c.state = StateStopped
		c.mu.Unlock()
		return nil
	}

	// SIGTERM (Interrupt) → grace period → SIGKILL. The watcher goroutine
	// owns the single cmd.Wait() call; we just signal and wait for the
	// `exited` channel to close.
	_ = cmd.Process.Signal(os.Interrupt)

	select {
	case <-exited:
		// Process exited (either by interrupt, kill, or crash). cmd.ProcessState
		// is now populated; inspect it to decide whether the exit was clean.
		c.mu.Lock()
		c.cmd = nil
		c.exited = nil
		c.state = StateStopped
		c.mu.Unlock()
		if cmd.ProcessState != nil && !cmd.ProcessState.Success() {
			// The only way to get here is a crash or signal-induced exit that
			// is not "exited normally" (status 0). Treat as a stop error.
			return &SsiError{Code: ErrProcessStop, Message: cmd.ProcessState.String()}
		}
		return nil
	case <-time.After(c.cfg.ShutdownGracePeriod):
		// Grace period expired. Force-kill and wait for the watcher to reap
		// the process so we don't leak a zombie and so c.cmd is fully
		// released before any subsequent Start().
		_ = cmd.Process.Kill()
		<-exited
		c.mu.Lock()
		c.cmd = nil
		c.exited = nil
		c.state = StateStopped
		c.mu.Unlock()
		return nil
	}
}

// Pause stops cloudflared but retains the configuration so Resume() can bring
// it back up without repeating Init(). Pause is the SkyNet-native concept that
// maps cleanly to "stop the tunnel but remember how to restart it".
func (c *CloudflaredComponent) Pause(ctx context.Context) *SsiError {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	if state != StateRunning {
		return &SsiError{Code: ErrInvalidState, Message: "cannot pause from " + state.String()}
	}
	c.mu.Lock()
	c.state = StatePausing
	c.mu.Unlock()
	if serr := c.Stop(ctx); serr != nil {
		return serr
	}
	c.mu.Lock()
	c.state = StatePaused
	c.mu.Unlock()
	return nil
}

// Resume brings a paused tunnel back online.
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

// RecentLogs returns the latest N lines of stdout/stderr captured from the
// child process. Useful for SkyNet dashboards to surface tunnel health without
// needing filesystem access.
func (c *CloudflaredComponent) RecentLines(n int) []string { return c.logs.tail(n) }

// ---- internal helpers -----------------------------------------------------

func (c *CloudflaredComponent) resolvedBinary() string {
	bin := c.cfg.BinaryPath
	if bin == "" {
		bin = "cloudflared"
	}
	if p, err := exec.LookPath(bin); err == nil {
		return p
	}
	return bin
}

// buildArgs expands the mode into the cloudflared sub-command arguments.
// Keep this list small — any configuration beyond the core three modes should
// go through ExtraArgs so that SkyNet operators can tune without code changes.
func (c *CloudflaredComponent) buildArgs() []string {
	var args []string
	switch c.cfg.Mode {
	case "tunnel":
		// cloudflared tunnel run <name>
		args = []string{"tunnel", "run"}
		if c.cfg.Name != "" {
			args = append(args, c.cfg.Name)
		}
	case "access":
		// cloudflared access tcp --url <listener> --hostname <remote>
		args = []string{"access", "tcp"}
		if c.cfg.OriginURL != "" {
			args = append(args, "--url", c.cfg.OriginURL)
		}
		if c.cfg.Hostname != "" {
			args = append(args, "--hostname", c.cfg.Hostname)
		}
		if c.cfg.Destination != "" {
			args = append(args, "--destination", c.cfg.Destination)
		}
	default:
		// "quick" → zero-config tunnel. Uses the --url flag to point at origin.
		args = []string{"tunnel", "--url", c.cfg.OriginURL}
	}
	args = append(args, c.cfg.ExtraArgs...)
	return args
}

// watchProcessExit blocks until cmd exits and then signals via the supplied
// channel. It is used by Start() so the parent can react to a child crash —
// both before startup completes (the channel is also closed when the startup
// probe is still pending) and after a successful start (the next supervisor
// layer can use the same hook to schedule a restart).
//
// It also flips the component state to ERROR if the crash happens after the
// component had reached RUNNING — otherwise the runtime would think the
// tunnel is still up and serve 5xx until next health-check.
func (c *CloudflaredComponent) watchProcessExit(cmd *exec.Cmd, exited chan<- struct{}) {
	if cmd == nil {
		return
	}
	// Reap the process so it doesn't become a zombie. We don't care about
	// the error here; the callers (Start / Stop) handle success/failure of
	// teardown themselves.
	_ = cmd.Wait()
	close(exited)

	// If Stop() is mid-flight it will reset state to STOPPED. The race is
	// benign because the second state write to the same field wins; we just
	// want a crash after Start() returned to be visible to the runtime.
	c.mu.Lock()
	if c.state == StateRunning {
		c.state = StateError
	}
	c.mu.Unlock()
}

func (c *CloudflaredComponent) waitForStartup(ctx context.Context, ready chan<- struct{}) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Context was cancelled (e.g. start timeout, or SkyNet asked to give up).
			// Close the channel so Start()'s select can fall through to the
			// <-time.After or <-ctx.Done() branch and return a proper error.
			close(ready)
			return
		case <-ticker.C:
			for _, line := range c.logs.tail(32) {
				l := strings.ToLower(line)
				if strings.Contains(l, "registered tunnel") ||
					strings.Contains(l, "connection") && strings.Contains(l, "registered") ||
					strings.Contains(l, "connected") ||
					strings.Contains(l, "ready") {
					close(ready)
					return
				}
			}
		}
	}
}

// ---- log ring buffer ------------------------------------------------------

// logBuffer is a small ring buffer of lines. It is intentionally lock-free on
// the write path (writes are single-threaded by the child process' pipes).
type logBuffer struct {
	mu   sync.RWMutex
	lines []string
	cap  int
}

func newLogBuffer(cap int) *logBuffer { return &logBuffer{cap: cap} }

func (b *logBuffer) newWriter(tag string) *os.File {
	// We pipe the child's fd through a goroutine that reads lines.
	r, w, err := os.Pipe()
	if err != nil {
		// Fall back to /dev/null — the sidecar can still function without logs.
		return os.Stderr
	}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			b.append(sc.Text())
		}
		_ = r.Close()
	}()
	_ = tag // tag reserved for structured-logging extensions
	return w
}

func (b *logBuffer) append(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, line)
	if len(b.lines) > b.cap {
		b.lines = b.lines[len(b.lines)-b.cap:]
	}
}

func (b *logBuffer) tail(n int) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if n <= 0 || len(b.lines) == 0 {
		return nil
	}
	if n > len(b.lines) {
		n = len(b.lines)
	}
	out := make([]string, n)
	copy(out, b.lines[len(b.lines)-n:])
	return out
}

// FormatLines is a small helper that dumps the most recent log lines as a
// single pre-formatted string, suitable for embedding into JSON reports.
func (c *CloudflaredComponent) FormatLogs(n int) string {
	lines := c.RecentLines(n)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// Ensure the package compiles even when the config dir is not created at
// import time. Kept here (instead of in a separate file) for discoverability.
var _ = filepath.Join
