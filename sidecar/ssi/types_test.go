package ssi

import (
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ParseConfig tests
// ---------------------------------------------------------------------------

func TestParseConfigDefault(t *testing.T) {
	// nil payload returns DefaultConfig.
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error on nil payload: %v", err)
	}
	if cfg.Name != "cloudflared-default" {
		t.Errorf("name = %q; want cloudflared-default", cfg.Name)
	}
	if cfg.Mode != "quick" {
		t.Errorf("mode = %q; want quick", cfg.Mode)
	}
	if cfg.Backend != "cloudflare" {
		t.Errorf("backend = %q; want cloudflare", cfg.Backend)
	}
	if cfg.ShutdownGracePeriod != 15*time.Second {
		t.Errorf("ShutdownGracePeriod = %v; want 15s", cfg.ShutdownGracePeriod)
	}
	if cfg.StartTimeout != 30*time.Second {
		t.Errorf("StartTimeout = %v; want 30s", cfg.StartTimeout)
	}
}

func TestParseConfigDefaultEmptyPayload(t *testing.T) {
	// Empty JSON payload also returns defaults.
	cfg, err := ParseConfig(json.RawMessage(""))
	if err != nil {
		t.Fatalf("unexpected error on empty payload: %v", err)
	}
	if cfg.Name != "cloudflared-default" {
		t.Errorf("name = %q; want cloudflared-default", cfg.Name)
	}
	if cfg.Mode != "quick" {
		t.Errorf("mode = %q; want quick", cfg.Mode)
	}
	if cfg.Backend != "cloudflare" {
		t.Errorf("backend = %q; want cloudflare", cfg.Backend)
	}
	if cfg.ShutdownGracePeriod != 15*time.Second {
		t.Errorf("ShutdownGracePeriod = %v; want 15s", cfg.ShutdownGracePeriod)
	}
	if cfg.StartTimeout != 30*time.Second {
		t.Errorf("StartTimeout = %v; want 30s", cfg.StartTimeout)
	}
}

func TestParseConfigCloudflareAllFields(t *testing.T) {
	payload := `{
		"name": "my-tunnel",
		"mode": "tunnel",
		"backend": "cloudflare",
		"origin_url": "https://example.com",
		"hostname": "tunnel.example.com",
		"destination": "10.0.0.1:3389",
		"binary_path": "/usr/local/bin/cloudflared",
		"extra_args": ["--loglevel", "debug"],
		"shutdown_grace_period_seconds": 5000000000,
		"start_timeout_seconds": 10000000000
	}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "my-tunnel" {
		t.Errorf("name = %q; want my-tunnel", cfg.Name)
	}
	if cfg.Mode != "tunnel" {
		t.Errorf("mode = %q; want tunnel", cfg.Mode)
	}
	if cfg.Backend != "cloudflare" {
		t.Errorf("backend = %q; want cloudflare", cfg.Backend)
	}
	if cfg.OriginURL != "https://example.com" {
		t.Errorf("origin_url = %q; want https://example.com", cfg.OriginURL)
	}
	if cfg.Hostname != "tunnel.example.com" {
		t.Errorf("hostname = %q; want tunnel.example.com", cfg.Hostname)
	}
	if cfg.Destination != "10.0.0.1:3389" {
		t.Errorf("destination = %q; want 10.0.0.1:3389", cfg.Destination)
	}
	if cfg.BinaryPath != "/usr/local/bin/cloudflared" {
		t.Errorf("binary_path = %q; want /usr/local/bin/cloudflared", cfg.BinaryPath)
	}
	if len(cfg.ExtraArgs) != 2 || cfg.ExtraArgs[0] != "--loglevel" || cfg.ExtraArgs[1] != "debug" {
		t.Errorf("extra_args = %v; want [--loglevel debug]", cfg.ExtraArgs)
	}
	if cfg.ShutdownGracePeriod != 5*time.Second {
		t.Errorf("ShutdownGracePeriod = %v; want 5s", cfg.ShutdownGracePeriod)
	}
	if cfg.StartTimeout != 10*time.Second {
		t.Errorf("StartTimeout = %v; want 10s", cfg.StartTimeout)
	}
}

func TestParseConfigCloudflareInvalidMode(t *testing.T) {
	_, err := ParseConfig(json.RawMessage(`{"backend":"cloudflare","mode":"bogus"}`))
	if err == nil {
		t.Fatal("expected error for unknown cloudflare mode")
	}
	if err.Code != ErrConfigInvalid {
		t.Errorf("error code = %d; want %d", err.Code, ErrConfigInvalid)
	}
}

func TestParseConfigProxyPool(t *testing.T) {
	payload := `{
		"name": "proxy-pool-instance",
		"backend": "proxy-pool",
		"proxy_listen": "127.0.0.1:1080"
	}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "proxy-pool-instance" {
		t.Errorf("name = %q; want proxy-pool-instance", cfg.Name)
	}
	if cfg.Backend != "proxy-pool" {
		t.Errorf("backend = %q; want proxy-pool", cfg.Backend)
	}
	if cfg.ProxyListen != "127.0.0.1:1080" {
		t.Errorf("proxy_listen = %q; want 127.0.0.1:1080", cfg.ProxyListen)
	}
}

func TestParseConfigFailover(t *testing.T) {
	cfg, err := ParseConfig(json.RawMessage(`{"backend":"failover"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend != "failover" {
		t.Errorf("backend = %q; want failover", cfg.Backend)
	}
}

func TestParseConfigSmartRouter(t *testing.T) {
	cfg, err := ParseConfig(json.RawMessage(`{"backend":"smart-router"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend != "smart-router" {
		t.Errorf("backend = %q; want smart-router", cfg.Backend)
	}
}

func TestParseConfigTCPRelayAllFields(t *testing.T) {
	payload := `{
		"name": "tcp-relay-1",
		"backend": "tcp-relay",
		"origin_url": "127.0.0.1:8080",
		"listen_address": "127.0.0.1:9090",
		"relay_target": "10.0.0.2:3306"
	}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "tcp-relay-1" {
		t.Errorf("name = %q; want tcp-relay-1", cfg.Name)
	}
	if cfg.Backend != "tcp-relay" {
		t.Errorf("backend = %q; want tcp-relay", cfg.Backend)
	}
	if cfg.OriginURL != "127.0.0.1:8080" {
		t.Errorf("origin_url = %q; want 127.0.0.1:8080", cfg.OriginURL)
	}
	if cfg.ListenAddress != "127.0.0.1:9090" {
		t.Errorf("listen_address = %q; want 127.0.0.1:9090", cfg.ListenAddress)
	}
	if cfg.RelayTarget != "10.0.0.2:3306" {
		t.Errorf("relay_target = %q; want 10.0.0.2:3306", cfg.RelayTarget)
	}
}

func TestParseConfigHTTPProxy(t *testing.T) {
	payload := `{
		"name": "http-proxy-1",
		"backend": "http-proxy",
		"proxy_listen": "0.0.0.0:3128"
	}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend != "http-proxy" {
		t.Errorf("backend = %q; want http-proxy", cfg.Backend)
	}
	if cfg.ProxyListen != "0.0.0.0:3128" {
		t.Errorf("proxy_listen = %q; want 0.0.0.0:3128", cfg.ProxyListen)
	}
}

func TestParseConfigSOCKS5(t *testing.T) {
	payload := `{
		"name": "socks5-1",
		"backend": "socks5",
		"proxy_listen": "0.0.0.0:1080"
	}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend != "socks5" {
		t.Errorf("backend = %q; want socks5", cfg.Backend)
	}
	if cfg.ProxyListen != "0.0.0.0:1080" {
		t.Errorf("proxy_listen = %q; want 0.0.0.0:1080", cfg.ProxyListen)
	}
}

func TestParseConfigSkynetP2P(t *testing.T) {
	payload := `{
		"name": "skynet-p2p-1",
		"backend": "skynet-p2p",
		"origin_url": "https://example.com"
	}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend != "skynet-p2p" {
		t.Errorf("backend = %q; want skynet-p2p", cfg.Backend)
	}
	if cfg.OriginURL != "https://example.com" {
		t.Errorf("origin_url = %q; want https://example.com", cfg.OriginURL)
	}
}

func TestParseConfigUnknownBackend(t *testing.T) {
	_, err := ParseConfig(json.RawMessage(`{"backend":"bogus"}`))
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
	if err.Code != ErrConfigInvalid {
		t.Errorf("error code = %d; want %d", err.Code, ErrConfigInvalid)
	}
}

func TestParseConfigInvalidJSON(t *testing.T) {
	_, err := ParseConfig(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if err.Code != ErrConfigInvalid {
		t.Errorf("error code = %d; want %d", err.Code, ErrConfigInvalid)
	}
}

func TestParseConfigEmptyNameDefaults(t *testing.T) {
	// When name is empty string (explicitly set), it should default to "cloudflared-default".
	cfg, err := ParseConfig(json.RawMessage(`{"name":""}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "cloudflared-default" {
		t.Errorf("name = %q; want cloudflared-default", cfg.Name)
	}
}

func TestParseConfigZeroDurationsGetDefaults(t *testing.T) {
	// Explicit zeros for durations should trigger defaults.
	payload := `{"name":"test","shutdown_grace_period_seconds":0,"start_timeout_seconds":0}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ShutdownGracePeriod != 15*time.Second {
		t.Errorf("ShutdownGracePeriod = %v; want 15s", cfg.ShutdownGracePeriod)
	}
	if cfg.StartTimeout != 30*time.Second {
		t.Errorf("StartTimeout = %v; want 30s", cfg.StartTimeout)
	}
}

func TestParseConfigNegativeDurationsGetDefaults(t *testing.T) {
	// Negative durations should also trigger defaults (<= 0 check).
	payload := `{"name":"test","shutdown_grace_period_seconds":-1,"start_timeout_seconds":-5}`
	cfg, err := ParseConfig(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ShutdownGracePeriod != 15*time.Second {
		t.Errorf("ShutdownGracePeriod = %v; want 15s", cfg.ShutdownGracePeriod)
	}
	if cfg.StartTimeout != 30*time.Second {
		t.Errorf("StartTimeout = %v; want 30s", cfg.StartTimeout)
	}
}

// ---------------------------------------------------------------------------
// ComponentState String() tests
// ---------------------------------------------------------------------------

func TestComponentStateString(t *testing.T) {
	tests := []struct {
		state ComponentState
		want  string
	}{
		{StateCreated, "CREATED"},
		{StateInitializing, "INITIALIZING"},
		{StateInitialized, "INITIALIZED"},
		{StateStarting, "STARTING"},
		{StateRunning, "RUNNING"},
		{StatePausing, "PAUSING"},
		{StatePaused, "PAUSED"},
		{StateResuming, "RESUMING"},
		{StateStopping, "STOPPING"},
		{StateStopped, "STOPPED"},
		{StateError, "ERROR"},
	}
	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("ComponentState(%d).String() = %q; want %q", int(tt.state), got, tt.want)
		}
	}
}

func TestComponentStateStringUnknown(t *testing.T) {
	unknown := ComponentState(99)
	got := unknown.String()
	if got != "UNKNOWN(99)" {
		t.Errorf("ComponentState(99).String() = %q; want UNKNOWN(99)", got)
	}
}

// ---------------------------------------------------------------------------
// SsiError.Error() tests
// ---------------------------------------------------------------------------

func TestSsiErrorError(t *testing.T) {
	tests := []struct {
		err  *SsiError
		want string
	}{
		{&SsiError{Code: 0, Message: "ok"}, "[SSI 0] ok"},
		{&SsiError{Code: 1, Message: "invalid state"}, "[SSI 1] invalid state"},
		{&SsiError{Code: 404, Message: "not found"}, "[SSI 404] not found"},
		{&SsiError{Code: -1, Message: ""}, "[SSI -1] "},
	}
	for _, tt := range tests {
		got := tt.err.Error()
		if got != tt.want {
			t.Errorf("SsiError{%d,%q}.Error() = %q; want %q", tt.err.Code, tt.err.Message, got, tt.want)
		}
	}
}

func TestSsiErrorNil(t *testing.T) {
	var e *SsiError = nil
	got := e.Error()
	if got != "<nil>" {
		t.Errorf("nil SsiError.Error() = %q; want <nil>", got)
	}
}
