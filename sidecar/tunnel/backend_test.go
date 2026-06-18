package tunnel

import "testing"

// ---------------------------------------------------------------------------
// NewBackend registration
// ---------------------------------------------------------------------------

func TestNewBackend_knownTypes(t *testing.T) {
	tests := []struct {
		name       string
		typeName   string
		wantNonNil bool
		wantErr    bool
	}{
		// empty → defaults to cloudflare
		{"empty defaults to cloudflare", "", true, false},
		{"cloudflare", TypeCloudflare, true, false},
		{"tcp-relay", TypeTCPRelay, true, false},
		{"skynet-p2p", TypeSkyNetP2P, true, false},
		{"http-proxy", TypeHTTPProxy, true, false},
		{"socks5", TypeSOCKS5, true, false},
		{"failover", TypeFailover, true, false},
		{"proxy-pool", TypeProxyPool, true, false},
		{"smart-router", "smart-router", true, false},
		{"gre", "gre", true, false},
		{"packet-tunnel", "packet-tunnel", true, false},
		{"udp-tunnel", "udp-tunnel", true, false},
		{"webrtc", "webrtc", true, false},
		{"quic", "quic", true, false},
		{"dns-tunnel", "dns-tunnel", true, false},
		{"icmp-tunnel", "icmp-tunnel", true, false},
		{"ssh-reverse", "ssh-reverse", true, false},
		{"dtls", "dtls", true, false},
		{"wireguard", "wireguard", true, false},
		{"rtsp", "rtsp", true, false},
		{"rtmp", "rtmp", true, false},
		{"sftp", "sftp", true, false},
		{"mqtt", "mqtt", true, false},
		// unknown → error
		{"unknown-type errors", "unknown-type", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewBackend(Config{Type: tt.typeName})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBackend(Type=%q) error = %v, wantErr = %v", tt.typeName, err, tt.wantErr)
			}
			if (got != nil) != tt.wantNonNil {
				t.Errorf("NewBackend(Type=%q) = %v, want non-nil = %v", tt.typeName, got, tt.wantNonNil)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Backend types have correct Type() string
// ---------------------------------------------------------------------------

func TestBackend_TypeString(t *testing.T) {
	tests := []struct {
		typeName     string
		expectedType string
	}{
		{"", TypeCloudflare},
		{TypeCloudflare, TypeCloudflare},
		{TypeTCPRelay, TypeTCPRelay},
		{TypeSkyNetP2P, TypeSkyNetP2P},
		{TypeHTTPProxy, TypeHTTPProxy},
		{TypeSOCKS5, TypeSOCKS5},
		{TypeFailover, "failover"},
		{TypeProxyPool, TypeProxyPool},
		{"smart-router", "smart-router"},
		{"gre", "gre"},
		{"packet-tunnel", "packet-tunnel"},
		{"udp-tunnel", "udp-tunnel"},
		{"webrtc", "webrtc"},
		{"quic", "quic"},
		{"dns-tunnel", "dns-tunnel"},
		{"icmp-tunnel", "icmp-tunnel"},
		{"ssh-reverse", "ssh-reverse"},
		{"dtls", "dtls"},
		{"wireguard", "wireguard"},
		{"rtsp", "rtsp"},
		{"rtmp", "rtmp"},
		{"sftp", "sftp"},
		{"mqtt", "mqtt"},
	}

	for _, tt := range tests {
		t.Run(tt.typeName, func(t *testing.T) {
			b, err := NewBackend(Config{Type: tt.typeName})
			if err != nil {
				t.Fatalf("NewBackend(Type=%q) unexpected error: %v", tt.typeName, err)
			}
			if b == nil {
				t.Fatalf("NewBackend(Type=%q) returned nil", tt.typeName)
			}
			if got := b.Type(); got != tt.expectedType {
				t.Errorf("b.Type() = %q, want %q", got, tt.expectedType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config defaults — empty Config defaults Type to "cloudflare"
// ---------------------------------------------------------------------------

func TestConfig_Defaults(t *testing.T) {
	b, err := NewBackend(Config{})
	if err != nil {
		t.Fatalf("NewBackend(Config{}) unexpected error: %v", err)
	}
	if b == nil {
		t.Fatal("NewBackend(Config{}) returned nil")
	}
	if got := b.Type(); got != TypeCloudflare {
		t.Errorf("Config{}.Type defaults to %q, want %q", got, TypeCloudflare)
	}
}

// ---------------------------------------------------------------------------
// parseBackendList
// ---------------------------------------------------------------------------

func TestParseBackendList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty string returns nil", "", nil},
		{"single entry", "cloudflare", []string{"cloudflare"}},
		{"multiple entries", "cloudflare,skynet-p2p,tcp-relay", []string{"cloudflare", "skynet-p2p", "tcp-relay"}},
		{"whitespace trimming", " cloudflare , skynet-p2p ", []string{"cloudflare", "skynet-p2p"}},
		{"empty parts skipped", "cloudflare,,skynet-p2p", []string{"cloudflare", "skynet-p2p"}},
		{"all whitespace parts", " , , ", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBackendList(tt.input)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseBackendList(%q) = %v (len=%d), want %v (len=%d)", tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseBackendList(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
