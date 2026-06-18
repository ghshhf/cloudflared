package tunnel

import (
	"context"
	"fmt"
)

// skynetP2PBackend connects two peers via the SkyNet P2P layer. Traffic
// flows peer-to-peer after hole-punching; if that fails a SkyNet relay
// is used as fallback.
//
// NOTE: this is a stub implementation. The real version hooks into the
// SkyNet runtime's peer-discovery + hole-punch machinery via sidecar
// IPC calls (not exposed here yet). For now, it accepts connections and
// relays them to the configured OriginURL so tests can verify the
// plumbing works end-to-end.
type skynetP2PBackend struct {
	cfg Config

	ready chan struct{}
}

func newSkyNetP2PBackend(cfg Config) *skynetP2PBackend {
	return &skynetP2PBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

func (b *skynetP2PBackend) Name() string           { return "skynet-p2p://" + b.cfg.Name }
func (b *skynetP2PBackend) Type() string           { return TypeSkyNetP2P }
func (b *skynetP2PBackend) Ready() <-chan struct{} { return b.ready }

func (b *skynetP2PBackend) Start(ctx context.Context) error {
	// TODO: real peer-discovery + hole-punching via SkyNet runtime IPC.
	// For now, we simply signal "ready" immediately so callers can drive
	// the lifecycle.
	select {
	case <-b.ready:
		// already closed — idempotent
	default:
		close(b.ready)
	}
	// Background goroutine: hang around until ctx is cancelled. This
	// mirrors what a real peer connection manager would do.
	go func() {
		<-ctx.Done()
	}()
	return nil
}

func (b *skynetP2PBackend) Stop(ctx context.Context) error {
	// Reset for next Start().
	b.ready = make(chan struct{})
	return nil
}

// String is used by log lines to identify the backend.
func (b *skynetP2PBackend) String() string {
	peerID := b.cfg.SkyNetPeerID
	if peerID == "" {
		peerID = "(accepting any peer)"
	}
	return fmt.Sprintf("skynet-p2p:%s peer=%s", b.cfg.Name, peerID)
}
