// Command cloudflared-sidecar is the SkyNet SSI wrapper around the native
// cloudflared binary. It is launched by the SkyNet runtime as a child process
// and communicates with it over stdin/stdout using JSON-RPC 2.0.
//
// Protocol reference: see ../ipc/bus.go. This file wires the ssi.IComponent
// implementation to the ipc.Bus dispatcher so that the runtime can invoke
// init / start / stop / pause / resume / get_state by name.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/dashboard"
	"github.com/cloudflare/cloudflared/sidecar/ipc"
	"github.com/cloudflare/cloudflared/sidecar/ssi"
)

// Version is injected at build time. See Makefile for ldflags.
// "dev" when built locally without ldflags.
var Version = "dev"

func main() {
	bus := ipc.NewBus(os.Stdin, os.Stdout)
	defer bus.Close()

	comp := ssi.NewCloudflaredComponent()

	// Optional web dashboard: enabled when SIDECAR_DASHBOARD_ADDR is set
	// (e.g. "127.0.0.1:8080"). Zero value disables the server entirely.
	dashboardAddr := os.Getenv("SIDECAR_DASHBOARD_ADDR")
	if dashboardAddr != "" {
		ds := dashboard.NewServer(dashboardAddr, comp)
		// Pass version string for display.
		ds.SetVersion(Version)
		// Read optional dashboard auth token from env.
		if token := os.Getenv("SIDECAR_DASHBOARD_TOKEN"); token != "" {
			ds.SetAuthToken(token)
		}
		// Wire proxy pool provider if the backend supports it.
		ds.SetPoolStatsProvider(comp)
		// Run with a context whose lifetime is the main process.
		ctx, cancel := context.WithCancel(context.Background())
		_ = cancel
		go func() {
			_ = ds.Start(ctx)
		}()
		ipc.DebugLog("sidecar dashboard listening on http://%s", dashboardAddr)
	}

	// Register the canonical SSI method names so the runtime can address this
	// sidecar by the standard component contract.
	bus.Register("init", wrapInit(comp))
	bus.Register("start", wrapStart(comp))
	bus.Register("stop", wrapStop(comp))
	bus.Register("pause", wrapPause(comp))
	bus.Register("resume", wrapResume(comp))
	bus.Register("get_state", wrapGetState(comp))
	bus.Register("get_logs", wrapGetLogs(comp))
	bus.Register("ping", func(_ context.Context, _ json.RawMessage) (any, error) {
		return map[string]string{"pong": time.Now().UTC().Format(time.RFC3339)}, nil
	})

	// Background state reporter. Every 30 seconds (or whenever the component
	// transitions), the sidecar pushes a state_changed notification so the
	// SkyNet dashboard does not have to poll. The goroutine is tied to the
	// bus lifecycle: when main returns, defer bus.Close() fires, which
	// cancels the bus context and unblocks this select via doneCh so we
	// don't leak the ticker goroutine.
	go heartbeat(bus, comp, bus.Done())

	// Exit on SIGINT / SIGTERM so we clean up if SkyNet kills us. Trap the
	// signal, stop the child component, *then* close the bus so the final
	// state_changed notification can be flushed. Without this ordering the
	// notify would be written to a closed bus and dropped.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = comp.Stop(ctx)
		bus.Close()
		os.Exit(0)
	}()

	ipc.DebugLog("sidecar ready; waiting for JSON-RPC on stdin...")
	if err := bus.Run(); err != nil {
		ipc.DebugLog("bus exit: %v", err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = comp.Stop(ctx)
		os.Exit(1)
	}
}

// heartbeat periodically reports component state. It also emits a
// state_changed notification whenever the state changes between ticks — that
// way the runtime learns about process crashes without having to poll.
// The doneCh lets the main goroutine ask us to exit on shutdown.
func heartbeat(bus *ipc.Bus, comp *ssi.CloudflaredComponent, doneCh <-chan struct{}) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()

	last := ssi.StateCreated
	emit := func(state ssi.ComponentState) {
		_ = bus.Notify("state_changed", map[string]any{
			"state":      state.String(),
			"state_code": int(state),
			"at":         time.Now().UTC().Format(time.RFC3339),
		})
	}
	// Emit once at startup so the runtime immediately knows we are alive.
	emit(last)

	for {
		select {
		case <-tick.C:
			now := comp.GetState()
			if now != last {
				emit(now)
				last = now
			}
		case <-doneCh:
			// Final emit on shutdown, then exit.
			emit(comp.GetState())
			return
		}
	}
}

// ---- JSON-RPC wrapper helpers ---------------------------------------------

func wrapInit(c *ssi.CloudflaredComponent) ipc.Handler {
	return func(ctx context.Context, params json.RawMessage) (any, error) {
		cfg, ssiErr := ssi.ParseConfig(params)
		if ssiErr != nil {
			return nil, fmt.Errorf("%s", ssiErr.Message)
		}
		if ssiErr := c.Init(ctx, cfg); ssiErr != nil {
			return nil, fmt.Errorf("%s", ssiErr.Message)
		}
		return map[string]any{"ok": true, "config": cfg}, nil
	}
}

func wrapStart(c *ssi.CloudflaredComponent) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, error) {
		if ssiErr := c.Start(ctx); ssiErr != nil {
			return nil, fmt.Errorf("%s", ssiErr.Message)
		}
		return map[string]any{"ok": true, "state": c.GetState().String()}, nil
	}
}

func wrapStop(c *ssi.CloudflaredComponent) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, error) {
		if ssiErr := c.Stop(ctx); ssiErr != nil {
			return nil, fmt.Errorf("%s", ssiErr.Message)
		}
		return map[string]any{"ok": true, "state": c.GetState().String()}, nil
	}
}

func wrapPause(c *ssi.CloudflaredComponent) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, error) {
		if ssiErr := c.Pause(ctx); ssiErr != nil {
			return nil, fmt.Errorf("%s", ssiErr.Message)
		}
		return map[string]any{"ok": true, "state": c.GetState().String()}, nil
	}
}

func wrapResume(c *ssi.CloudflaredComponent) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, error) {
		if ssiErr := c.Resume(ctx); ssiErr != nil {
			return nil, fmt.Errorf("%s", ssiErr.Message)
		}
		return map[string]any{"ok": true, "state": c.GetState().String()}, nil
	}
}

func wrapGetState(c *ssi.CloudflaredComponent) ipc.Handler {
	return func(_ context.Context, _ json.RawMessage) (any, error) {
		state := c.GetState()
		return map[string]any{
			"state":      state.String(),
			"state_code": int(state),
		}, nil
	}
}

func wrapGetLogs(c *ssi.CloudflaredComponent) ipc.Handler {
	return func(_ context.Context, params json.RawMessage) (any, error) {
		n := 64
		var p map[string]int
		if len(params) > 0 {
			_ = json.Unmarshal(params, &p)
			if v, ok := p["n"]; ok && v > 0 {
				n = v
			}
		}
		return map[string]any{"lines": c.RecentLines(n)}, nil
	}
}
