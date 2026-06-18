package tunnel

import (
	"context"
	"strings"
	"testing"
)

// backendsLifecycleTest verifies that every backend type can be constructed,
// reports the correct Name/Type, has a non-nil Ready channel, and handles
// Stop() on a never-started backend without panicking.
//
// Start() is NOT called here because most backends need actual network
// resources (listeners, dials, etc.) that aren't available in unit tests.

type backendCase struct {
	name     string
	cfg      Config
	wantType string
}

func TestAllBackendsConstruction(t *testing.T) {
	cases := []backendCase{
		{name: "cloudflare-default", cfg: Config{Name: "cf", OriginURL: "http://localhost:8080"}, wantType: TypeCloudflare},
		{name: "tcp-relay", cfg: Config{Name: "tcp", Type: TypeTCPRelay, OriginURL: "127.0.0.1:9090"}, wantType: TypeTCPRelay},
		{name: "skynet-p2p", cfg: Config{Name: "p2p", Type: TypeSkyNetP2P}, wantType: TypeSkyNetP2P},
		{name: "http-proxy", cfg: Config{Name: "http", Type: TypeHTTPProxy}, wantType: TypeHTTPProxy},
		{name: "socks5", cfg: Config{Name: "socks", Type: TypeSOCKS5}, wantType: TypeSOCKS5},
		{name: "gre", cfg: Config{Name: "gre1", Type: "gre"}, wantType: "gre"},
		{name: "packet-tunnel", cfg: Config{Name: "vxlan1", Type: "packet-tunnel"}, wantType: "packet-tunnel"},
		{name: "udp-tunnel", cfg: Config{Name: "udp1", Type: "udp-tunnel"}, wantType: "udp-tunnel"},
		{name: "dns-tunnel", cfg: Config{Name: "dns1", Type: "dns-tunnel"}, wantType: "dns-tunnel"},
		{name: "icmp-tunnel", cfg: Config{Name: "icmp1", Type: "icmp-tunnel"}, wantType: "icmp-tunnel"},
		{name: "quic", cfg: Config{Name: "quic1", Type: "quic"}, wantType: "quic"},
		{name: "dtls", cfg: Config{Name: "dtls1", Type: "dtls"}, wantType: "dtls"},
		{name: "wireguard", cfg: Config{Name: "wg1", Type: "wireguard"}, wantType: "wireguard"},
		{name: "rtsp", cfg: Config{Name: "rtsp1", Type: "rtsp"}, wantType: "rtsp"},
		{name: "rtmp", cfg: Config{Name: "rtmp1", Type: "rtmp"}, wantType: "rtmp"},
		{name: "sftp", cfg: Config{Name: "sftp1", Type: "sftp"}, wantType: "sftp"},
		{name: "mqtt", cfg: Config{Name: "mqtt1", Type: "mqtt"}, wantType: "mqtt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be, err := NewBackend(tc.cfg)
			if err != nil {
				t.Fatalf("NewBackend(%+v) error: %v", tc.cfg, err)
			}
			if be == nil {
				t.Fatal("NewBackend returned nil")
			}

			// Name() returns the configured name.
			if !strings.Contains(be.Name(), tc.cfg.Name) {
				t.Errorf("Name() = %q; should contain %q", be.Name(), tc.cfg.Name)
			}

			// Type() returns the expected canonical type.
			if be.Type() != tc.wantType {
				t.Errorf("Type() = %q; want %q", be.Type(), tc.wantType)
			}

			// Ready() returns a non-nil channel.
			if be.Ready() == nil {
				t.Error("Ready() returned nil channel")
			}

			// Stop() on a never-started backend must not panic.
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Stop() panicked on never-started backend: %v", r)
					}
				}()
				_ = be.Stop(context.Background())
			}()
		})
	}
}

// TestNewBackendUnknown verifies unknown backend type returns an error.
func TestNewBackendUnknown(t *testing.T) {
	_, err := NewBackend(Config{Name: "unknown", Type: "bogus-protocol"})
	if err == nil {
		t.Fatal("expected error for unknown backend type")
	}
}

// TestDefaultBackend verifies empty type defaults to cloudflare.
func TestDefaultBackend(t *testing.T) {
	be, err := NewBackend(Config{Name: "default"})
	if err != nil {
		t.Fatalf("NewBackend with empty type: %v", err)
	}
	if be.Type() != TypeCloudflare {
		t.Errorf("Type() = %q; want %q", be.Type(), TypeCloudflare)
	}
}
