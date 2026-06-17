// Package ssi implements the SkyNet SSI v1.0 component lifecycle for the
// cloudflared sidecar. The sidecar does not re-compile cloudflared to WASM;
// instead it wraps the native cloudflared binary so that SkyNet can manage
// tunnel instances through a standardised IComponent interface.
package ssi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ComponentState mirrors SsiComponentState from the SkyNet SSI spec.
type ComponentState int

const (
	StateCreated      ComponentState = 0
	StateInitializing ComponentState = 1
	StateInitialized  ComponentState = 2
	StateStarting     ComponentState = 3
	StateRunning      ComponentState = 4
	StatePausing      ComponentState = 5
	StatePaused       ComponentState = 6
	StateResuming     ComponentState = 7
	StateStopping     ComponentState = 8
	StateStopped      ComponentState = 9
	StateError        ComponentState = 10
)

func (s ComponentState) String() string {
	switch s {
	case StateCreated:
		return "CREATED"
	case StateInitializing:
		return "INITIALIZING"
	case StateInitialized:
		return "INITIALIZED"
	case StateStarting:
		return "STARTING"
	case StateRunning:
		return "RUNNING"
	case StatePausing:
		return "PAUSING"
	case StatePaused:
		return "PAUSED"
	case StateResuming:
		return "RESUMING"
	case StateStopping:
		return "STOPPING"
	case StateStopped:
		return "STOPPED"
	case StateError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// SsiError mirrors the standard error type used across the SSI bus.
type SsiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *SsiError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("[SSI %d] %s", e.Code, e.Message)
}

// Common SSI error codes (small subset; projects can extend).
const (
	ErrOk            = 0
	ErrInvalidState  = 1
	ErrConfigInvalid = 2
	ErrProcessStart  = 3
	ErrProcessStop   = 4
	ErrProcessCrashed = 5
	ErrIPC           = 6
	ErrNotFound      = 7
)

// Config is the on-the-wire configuration accepted by the cloudflared sidecar.
// It is deliberately flat so that SkyNet can dispatch the same JSON payload to
// either a "tunnel" or an "access" sub-component.
type Config struct {
	// Name identifies this tunnel to the SkyNet runtime; used as label in logs
	// and metrics only.
	Name string `json:"name"`

	// Mode selects the cloudflared invocation shape.
	//  - "quick"    -> cloudflared tunnel --url <OriginURL>  (zero-config, free)
	//  - "tunnel"   -> cloudflared tunnel run <NameOrUUID>   (registered tunnel)
	//  - "access"   -> cloudflared access tcp --url ...      (access tcp forward)
	Mode string `json:"mode"`

	// OriginURL is forwarded verbatim to cloudflared --url for "quick" mode or
	// as --url for "access" mode. Ignored for the "tunnel" mode.
	OriginURL string `json:"origin_url,omitempty"`

	// Hostname is the --hostname value for access tcp mode (public DNS name of
	// the Access-protected application).
	Hostname string `json:"hostname,omitempty"`

	// Destination is the --destination value (the RDP/SSH server reachable from
	// inside the private network).
	Destination string `json:"destination,omitempty"`

	// BinaryPath points at the cloudflared executable. If empty the sidecar
	// falls back to looking up "cloudflared" on $PATH.
	BinaryPath string `json:"binary_path,omitempty"`

	// ExtraArgs are appended after cloudflared's sub-command. They let the
	// operator pass flags such as --loglevel, --pidfile, --metrics, etc.
	ExtraArgs []string `json:"extra_args,omitempty"`

	// ShutdownGracePeriod controls how long we wait between SIGTERM and SIGKILL.
	ShutdownGracePeriod time.Duration `json:"shutdown_grace_period_seconds,omitempty"`

	// StartTimeout is the maximum time allowed for cloudflared to establish its
	// first connection to the Cloudflare edge before we mark it ERROR.
	StartTimeout time.Duration `json:"start_timeout_seconds,omitempty"`
}

// DefaultConfig returns sensible defaults so callers can send a minimal JSON
// payload and still get a working tunnel.
func DefaultConfig() Config {
	return Config{
		Name:                "cloudflared-default",
		Mode:                "quick",
		ShutdownGracePeriod: 15 * time.Second,
		StartTimeout:        30 * time.Second,
	}
}

// ParseConfig decodes a JSON byte slice into a Config, applying defaults for
// any field that was omitted. Returned *SsiError is typed so callers can send
// it straight back on the IPC bus.
func ParseConfig(payload json.RawMessage) (Config, *SsiError) {
	cfg := DefaultConfig()
	if len(payload) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return cfg, &SsiError{Code: ErrConfigInvalid, Message: "invalid JSON: " + err.Error()}
	}
	if cfg.Name == "" {
		cfg.Name = "cloudflared-default"
	}
	if cfg.Mode == "" {
		cfg.Mode = "quick"
	}
	switch cfg.Mode {
	case "quick", "tunnel", "access":
	default:
		return cfg, &SsiError{Code: ErrConfigInvalid, Message: "unknown mode: " + cfg.Mode}
	}
	if cfg.ShutdownGracePeriod <= 0 {
		cfg.ShutdownGracePeriod = 15 * time.Second
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = 30 * time.Second
	}
	return cfg, nil
}

// IComponent is the standardised component interface every SkyNet component
// must expose. Names match the C function pointers in the SSI v1.0 spec.
type IComponent interface {
	Init(ctx context.Context, cfg Config) *SsiError
	Start(ctx context.Context) *SsiError
	Stop(ctx context.Context) *SsiError
	Pause(ctx context.Context) *SsiError
	Resume(ctx context.Context) *SsiError
	GetState() ComponentState
}
