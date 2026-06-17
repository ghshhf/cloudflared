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
// Fields are deliberately narrow so the IPC bus stays stable; any backend-
// specific knob (e.g. "listen address", "relay target") lives alongside the
// core fields below.
//
// When Backend is empty ("") we default to "cloudflare" so we stay compatible
// with existing SkyNet runtimes that do not know about the multi-backend
// architecture.
type Config struct {
	// Name identifies this tunnel to the SkyNet runtime; used as label
	// in logs and metrics.
	Name string `json:"name"`

	// Mode selects the cloudflared invocation shape.
	//  - "quick"  -> cloudflared tunnel --url <OriginURL> (zero-config free)
	//  - "tunnel" -> cloudflared tunnel run <Name>        (registered tunnel)
	//  - "access" -> cloudflared access tcp --url ...     (access tcp proxy)
	// Only used by the "cloudflare" backend; ignored for backends such as
	// "tcp-relay", "skynet-p2p", "http-proxy", "socks5".
	Mode string `json:"mode"`

	// Backend selects the pluggable Backend that carries traffic.
	// Values: "cloudflare" (default), "tcp-relay", "skynet-p2p",
	// "http-proxy", "socks5".
	Backend string `json:"backend,omitempty"`

	// OriginURL is forwarded verbatim to cloudflared --url for "quick" mode,
	// or used as the default upstream target for "tcp-relay".
	OriginURL string `json:"origin_url,omitempty"`

	// Hostname is the --hostname value for access tcp mode (public DNS name
	// of the Access-protected application).
	Hostname string `json:"hostname,omitempty"`

	// Destination is the --destination value (the RDP/SSH server reachable
	// from inside the private network).
	Destination string `json:"destination,omitempty"`

	// BinaryPath points at the cloudflared executable. If empty the sidecar
	// falls back to looking up "cloudflared" on $PATH. Only used by the
	// "cloudflare" backend.
	BinaryPath string `json:"binary_path,omitempty"`

	// ExtraArgs are appended after cloudflared's sub-command. They let the
	// operator pass flags such as --loglevel, --pidfile, --metrics, etc.
	ExtraArgs []string `json:"extra_args,omitempty"`

	// --- backend-specific knobs --------------------------------------

	// ListenAddress is the host:port the TCP-relay backend listens on.
	// If empty the OS picks a free port. Only used by "tcp-relay".
	ListenAddress string `json:"listen_address,omitempty"`

	// RelayTarget is the upstream host:port the TCP relay forwards to.
	// If empty falls back to OriginURL. Only used by "tcp-relay".
	RelayTarget string `json:"relay_target,omitempty"`

	// ProxyListen is the local host:port the HTTP/SOCKS5 proxy backend
	// binds to. Only used by "http-proxy" and "socks5".
	ProxyListen string `json:"proxy_listen,omitempty"`

	// --- lifecycle tuning --------------------------------------------

	// ShutdownGracePeriod controls how long we wait between SIGTERM and SIGKILL.
	ShutdownGracePeriod time.Duration `json:"shutdown_grace_period_seconds,omitempty"`

	// StartTimeout is the maximum time allowed for the backend to establish
	// its tunnel before we mark it ERROR.
	StartTimeout time.Duration `json:"start_timeout_seconds,omitempty"`
}

// DefaultConfig returns sensible defaults so callers can send a minimal
// JSON payload and still get a working tunnel. "cloudflare" is the default
// backend for historical reasons — it maps to the cloudflared binary.
func DefaultConfig() Config {
	return Config{
		Name:                "cloudflared-default",
		Mode:                "quick",
		Backend:             "cloudflare",
		ShutdownGracePeriod: 15 * time.Second,
		StartTimeout:        30 * time.Second,
	}
}

// ParseConfig decodes a JSON byte slice into a Config, applying defaults for
// any field that was omitted. Returned *SsiError is typed so callers can send
// it straight back on the IPC bus.
//
// The "backend" field is optional — empty defaults to "cloudflare". Unknown
// backends are rejected at Init time (not here), so a configuration file with
// a typo is caught early but without being too strict at parse time.
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
	if cfg.Backend == "" {
		cfg.Backend = "cloudflare"
	}
	switch cfg.Backend {
	case "cloudflare":
		// Cloudflare backend has its own mode validation.
		switch cfg.Mode {
		case "quick", "tunnel", "access":
		default:
			return cfg, &SsiError{Code: ErrConfigInvalid, Message: "unknown mode: " + cfg.Mode}
		}
	case "tcp-relay", "skynet-p2p", "http-proxy", "socks5", "failover", "smart-router", "proxy-pool":
		// Non-cloudflare backends don't need a mode.
	default:
		return cfg, &SsiError{Code: ErrConfigInvalid, Message: "unknown backend: " + cfg.Backend}
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
