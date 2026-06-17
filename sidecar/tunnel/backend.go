// Package tunnel defines the pluggable backend interface for the
// cloudflared sidecar. Conceptually a "backend" is anything that can
// accept inbound traffic from the outside world and deliver it to a
// local origin service:
//
//   - Cloudflare Tunnel (the original cloudflared binary path)
//   - TCP Relay (a simple self-hosted tunnel)
//   - SkyNet P2P (direct device-to-device communication over the
//     SkyNet peer-to-peer layer)
//   - … more backends to come (WireGuard, SOCKS-chain, etc.)
//
// Every backend exposes the same four lifecycle hooks so the sidecar
// does not have to know anything about *how* the tunnel works.
package tunnel

import (
	"context"
	"strings"

	"github.com/cloudflare/cloudflared/sidecar/router"
	"github.com/cloudflare/cloudflared/sidecar/webrtc"
)

// Backend is the common interface implemented by every tunnel backend.
// Backends are lightweight, stateful objects: one instance manages one
// tunnel (one origin → one public entry point).
//
// Lifecycle:
//
//	NewBackend(Config) → Start(ctx) → [ Ready() signals tunnel up ]
//	                          ↓
//	                    Stop(ctx) ←  (runtime asks shutdown)
//
// Name/Type are informational; they let the runtime label the tunnel
// in dashboards and log lines.
type Backend interface {
	// Name returns a short human-readable identifier for this backend
	// instance. Example: "cloudflare://my-tunnel" or "skynet://device1".
	Name() string

	// Type returns the backend's canonical type name. One of the
	// BackendType constants below. Useful for logging/metrics.
	Type() string

	// Start brings up the tunnel. Blocks until the tunnel is ready,
	// the context expires, or the tunnel fails to come up. Returning
	// nil means "tunnel up and serving"; returning an error puts the
	// component in the ERROR state.
	//
	// Start MUST be safe to call after Stop returns (i.e. the
	// implementation must be able to recycle its resources).
	Start(ctx context.Context) error

	// Stop tears down the tunnel. Must be idempotent and safe to call
	// on a never-started backend. The implementation is responsible for
	// releasing file descriptors, goroutines, and child processes.
	Stop(ctx context.Context) error

	// Ready returns a channel that is closed when the backend believes
	// the tunnel is forwarding traffic. Used by the startup probe in
	// place of log-line parsing (cloudflared) or connection probes
	// (everything else).
	Ready() <-chan struct{}
}

// Canonical backend-type constants. The strings also appear in the
// JSON configuration payload (`backend` field).
const (
	TypeCloudflare = "cloudflare" // wrap the official cloudflared binary
	TypeTCPRelay   = "tcp-relay"  // simple self-hosted TCP tunnel
	TypeSkyNetP2P  = "skynet-p2p" // device-to-device over SkyNet P2P layer
	TypeHTTPProxy  = "http-proxy" // local HTTP CONNECT proxy over tunnel
	TypeSOCKS5     = "socks5"     // local SOCKS5 proxy over tunnel
	TypeFailover   = "failover"   // aggregate of backends, auto-failover
	TypeProxyPool  = "proxy-pool" // dynamic free proxy pool from subscription sources
)

// ---- configuration helpers --------------------------------------------

// parseBackendList parses a comma-separated list of backend types.
// Unknown entries silently map to TypeCloudflare. Example:
//
//	"cloudflare,skynet-p2p,tcp-relay"
//	-> [ TypeCloudflare, TypeSkyNetP2P, TypeTCPRelay ]
func parseBackendList(list string) []string {
	if list == "" {
		return nil
	}
	parts := strings.Split(list, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// Config is the backend-agnostic configuration. Backends read only
// the fields they understand; the component layer passes the same
// struct to every backend so adding new fields does not require
// changing the plumbing.
type Config struct {
	// Type selects which backend to run.
	// Values: "cloudflare" (default), "tcp-relay", "skynet-p2p".
	Type string `json:"backend"`

	// --- fields used by most backends ---

	// OriginURL (or host:port) is the local service the tunnel points
	// at. For "cloudflare" mode this is the --url argument; for
	// "tcp-relay" this is the upstream host:port.
	OriginURL string `json:"origin_url"`

	// Name is a logical label used in logs and metrics.
	Name string `json:"name"`

	// CloudflareBinary is the path to the cloudflared executable.
	// Empty means "look up cloudflared on $PATH". Only used by the
	// "cloudflare" backend.
	CloudflareBinary string `json:"cloudflare_binary,omitempty"`

	// Mode selects the cloudflared invocation shape. One of
	// "quick", "tunnel", "access". Only used by the "cloudflare" backend.
	CloudflareMode string `json:"cloudflare_mode,omitempty"`

	// --- TCP Relay backend ---

	// ListenAddress is the host:port the TCP relay listens on for
	// inbound connections. Only used by "tcp-relay".
	ListenAddress string `json:"listen_address,omitempty"`

	// RelayTarget is the host:port the TCP relay forwards connections
	// to. If empty the backend falls back to OriginURL. Only used by
	// "tcp-relay".
	RelayTarget string `json:"relay_target,omitempty"`

	// --- SkyNet P2P backend ---

	// SkyNetPeerID is the peer to connect to. If empty and SkyNet has
	// active peers, the backend will accept connections from any peer.
	// "skynet-p2p" only.
	SkyNetPeerID string `json:"skynet_peer_id,omitempty"`

	// SkyNetProtocolName identifies this tunnel on the SkyNet P2P
	// layer. A stable protocol name lets peers find each other.
	// "skynet-p2p" only. Default: "/skynet-tunnel/1.0.0".
	SkyNetProtocolName string `json:"skynet_protocol_name,omitempty"`

	// --- HTTP / SOCKS5 proxy backends ---

	// ProxyListen is the local host:port the proxy listener binds to.
	// "http-proxy" and "socks5" backends only.
	ProxyListen string `json:"proxy_listen,omitempty"`

	// --- shared lifecycle tuning ---

	// ShutdownGracePeriod is the SIGTERM → SIGKILL grace window for
	// backends that manage child processes (cloudflare backend) or
	// long-lived connections (tcp-relay).
	ShutdownGracePeriodSeconds float64 `json:"shutdown_grace_period_seconds,omitempty"`

	// StartTimeout is the maximum time a backend may take to reach
	// Ready during Start() before the component marks it ERROR.
	StartTimeoutSeconds float64 `json:"start_timeout_seconds,omitempty"`

	// ExtraArgs are passed verbatim to child-process backends such
	// as "cloudflare". Ignored by in-process backends.
	ExtraArgs []string `json:"extra_args,omitempty"`

	// AccessHostname / Destination are cloudflare-access-mode only.
	AccessHostname    string `json:"access_hostname,omitempty"`
	AccessDestination string `json:"access_destination,omitempty"`

	// --- smart-router / failover specific ---

	// RoutingMode selects the routing strategy.
	// Values: "failover" (default), "round-robin", "latency", "sticky", "p2p-first".
	RoutingMode string `json:"routing_mode,omitempty"`

	// PreferP2P causes the router to always prefer P2P backends when healthy.
	PreferP2P bool `json:"prefer_p2p,omitempty"`

	// RoutingRules is a JSON array of routing rules for the smart-router.
	// Each rule: {dest: "10.0.0.0/8", proto: "tcp", backend: "skynet-p2p", priority: 100}
	RoutingRules []string `json:"routing_rules,omitempty"`

	// GREKey is the GRE key used for GRE and packet-tunnel backends.
	GREKey uint32 `json:"gre_key,omitempty"`

	// Servers is a list of server addresses used by backends that need external
	// discovery (STUN for WebRTC, TURN for relay, etc.).
	Servers []string `json:"servers,omitempty"`

	// TunnelDomain is the DNS domain used for DNS tunnel.
	// Subdomains of this domain carry tunneled data.
	TunnelDomain string `json:"tunnel_domain,omitempty"`
}

// NewBackend is the backend registry: given a Config it returns a
// ready-to-start Backend. Call Start() to bring the tunnel up.
//
// Returns an error only if cfg.Type names an unknown backend.
// (Validation of individual backend parameters happens inside Start
// so we can surface rich errors through the SkyNet IPC bus.)
func NewBackend(cfg Config) (Backend, error) {
	switch cfg.Type {
	case TypeCloudflare, "":
		return newCloudflareBackend(cfg), nil
	case TypeTCPRelay:
		return newTCPRelayBackend(cfg), nil
	case TypeSkyNetP2P:
		return newSkyNetP2PBackend(cfg), nil
	case TypeHTTPProxy:
		return newHTTPProxyBackend(cfg), nil
	case TypeSOCKS5:
		return newSOCKS5Backend(cfg), nil
	case TypeFailover:
		// "Failover" aggregates multiple child backends whose types
		// are declared in cfg.ExtraArgs as a comma-separated list.
		// Example: cfg.ExtraArgs = ["cloudflare","skynet-p2p","tcp-relay"]
		var childTypes []string
		if len(cfg.ExtraArgs) > 0 {
			childTypes = parseBackendList(strings.Join(cfg.ExtraArgs, ","))
		}
		if len(childTypes) == 0 {
			childTypes = []string{TypeCloudflare, TypeSkyNetP2P} // default
		}
		children := make([]Backend, 0, len(childTypes))
		for _, t := range childTypes {
			childCfg := cfg
			childCfg.Type = t
			childCfg.Name = cfg.Name + "-" + t
			child, err := NewBackend(childCfg)
			if err != nil {
				return nil, err
			}
			children = append(children, child)
		}
		return newFailoverBackend(cfg, children...), nil

	case TypeProxyPool:
		return newProxyPoolBackend(cfg), nil

	case "smart-router":
		// Smart-router is configured via cfg.RoutingRules (JSON array of rules)
		// and cfg.RoutingMode (failover | round-robin | latency | sticky | p2p-first).
		// Its child backends are declared in cfg.ExtraArgs (same format as failover).
		routerCfg := router.Config{
			Mode:      router.Mode(cfg.RoutingMode),
			PreferP2P: cfg.PreferP2P,
		}
		var childTypes []string
		if len(cfg.ExtraArgs) > 0 {
			childTypes = parseBackendList(strings.Join(cfg.ExtraArgs, ","))
		}
		if len(childTypes) == 0 {
			childTypes = []string{TypeCloudflare, TypeSkyNetP2P, TypeTCPRelay}
		}
		r, err := router.New(routerCfg)
		if err != nil {
			return nil, err
		}
		for _, t := range childTypes {
			childCfg := cfg
			childCfg.Type = t
			childCfg.Name = cfg.Name + "-" + t
			child, err := NewBackend(childCfg)
			if err != nil {
				return nil, err
			}
			r.RegisterBackend(t, child)
		}
		return r, nil

	case "gre":
		return newGREBackend(cfg), nil
	case "packet-tunnel":
		return newPacketTunnelBackend(cfg), nil
	case "udp-tunnel":
		return newUDPTunnelBackend(cfg), nil
	case "webrtc":
		return webrtc.NewWebRTCBackend(webrtc.STUNConfig{
			ListenAddr:  cfg.ListenAddress,
			STUNServers: cfg.Servers,
			Label:       cfg.Name,
			ProtocolID:  cfg.SkyNetProtocolName,
		}), nil
	case "quic":
		return newQUICBackend(cfg), nil
	case "dns-tunnel":
		return newDNSTunnelBackend(cfg), nil
	case "icmp-tunnel":
		return newICMPTunnelBackend(cfg), nil
	case "ssh-reverse":
		return newSSHReverseBackend(cfg), nil
	case "dtls":
		return newDTLSBackend(cfg), nil
	case "wireguard":
		return newWireGuardBackend(cfg), nil
	case "rtsp":
		return newRTSPBackend(cfg), nil
	case "rtmp":
		return newRTMPBackend(cfg), nil
	case "sftp":
		return newSFTPBackend(cfg), nil
	case "mqtt":
		return newMQTTBackend(cfg), nil

	default:
		return nil, errUnknownBackend(cfg.Type)
	}
}

func errUnknownBackend(t string) error {
	return &backendErr{msg: "unknown backend: " + t}
}

type backendErr struct{ msg string }

func (e *backendErr) Error() string { return "[tunnel] " + e.msg }
