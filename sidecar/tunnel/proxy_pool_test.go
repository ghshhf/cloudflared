package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// tryDecodeBase64
// ---------------------------------------------------------------------------

func TestTryDecodeBase64(t *testing.T) {
	t.Run("standard base64", func(t *testing.T) {
		raw := base64.StdEncoding.EncodeToString([]byte(`hello world`))
		got, err := tryDecodeBase64(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "hello world" {
			t.Fatalf("got %q, want %q", got, "hello world")
		}
	})

	t.Run("url safe base64", func(t *testing.T) {
		raw := base64.URLEncoding.EncodeToString([]byte(`{"add":"host.com","port":443}`))
		got, err := tryDecodeBase64(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, `"add"`) {
			t.Fatalf("unexpected decoded output: %s", got)
		}
	})

	t.Run("standard with url-safe content", func(t *testing.T) {
		// URL-safe content that standard base64 cannot decode but URL-safe can.
		raw := base64.URLEncoding.EncodeToString([]byte(`data`))
		got, err := tryDecodeBase64(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "data" {
			t.Fatalf("got %q, want %q", got, "data")
		}
	})

	t.Run("padding fix for missing padding", func(t *testing.T) {
		// Standard b64 of "hello" is "aGVsbG8=", remove padding → "aGVsbG8"
		raw := base64.StdEncoding.EncodeToString([]byte(`hello`))
		raw = strings.TrimRight(raw, "=") // remove padding
		got, err := tryDecodeBase64(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "hello" {
			t.Fatalf("got %q, want %q", got, "hello")
		}
	})

	t.Run("padding fix with 2 missing chars", func(t *testing.T) {
		raw := base64.StdEncoding.EncodeToString([]byte(`abcd`))
		raw = strings.TrimRight(raw, "=")
		got, err := tryDecodeBase64(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "abcd" {
			t.Fatalf("got %q, want %q", got, "abcd")
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		_, err := tryDecodeBase64("!!!not-base64!!!")
		if err == nil {
			t.Fatal("expected error for invalid base64 input")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		got, err := tryDecodeBase64("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("got %q, want empty string", got)
		}
	})
}

// ---------------------------------------------------------------------------
// extractVMessHost
// ---------------------------------------------------------------------------

func TestExtractVMessHost(t *testing.T) {
	t.Run("valid base64 json", func(t *testing.T) {
		v := map[string]interface{}{"add": "1.2.3.4", "port": 443, "id": "uuid"}
		b, _ := json.Marshal(v)
		encoded := base64.StdEncoding.EncodeToString(b)
		got := extractVMessHost(encoded)
		want := "1.2.3.4:443"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("valid base64 json with different host port", func(t *testing.T) {
		v := map[string]interface{}{"add": "proxy.example.com", "port": 8080, "id": "abcd-1234"}
		b, _ := json.Marshal(v)
		encoded := base64.StdEncoding.EncodeToString(b)
		got := extractVMessHost(encoded)
		want := "proxy.example.com:8080"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		got := extractVMessHost("!!!not-base64!!!")
		if got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})

	t.Run("not json after decode", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`just-plain-text`))
		got := extractVMessHost(encoded)
		if got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})

	t.Run("empty add field", func(t *testing.T) {
		v := map[string]interface{}{"add": "", "port": 443, "id": "uuid"}
		b, _ := json.Marshal(v)
		encoded := base64.StdEncoding.EncodeToString(b)
		got := extractVMessHost(encoded)
		if got != "" {
			t.Fatalf("expected empty string for empty add, got %q", got)
		}
	})

	t.Run("zero port", func(t *testing.T) {
		v := map[string]interface{}{"add": "1.2.3.4", "port": 0, "id": "uuid"}
		b, _ := json.Marshal(v)
		encoded := base64.StdEncoding.EncodeToString(b)
		got := extractVMessHost(encoded)
		if got != "" {
			t.Fatalf("expected empty string for zero port, got %q", got)
		}
	})

	t.Run("empty json object", func(t *testing.T) {
		v := map[string]interface{}{}
		b, _ := json.Marshal(v)
		encoded := base64.StdEncoding.EncodeToString(b)
		got := extractVMessHost(encoded)
		if got != "" {
			t.Fatalf("expected empty string for empty json, got %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// fetchTextLines
// ---------------------------------------------------------------------------

func TestFetchTextLines(t *testing.T) {
	t.Run("success with multiple lines", func(t *testing.T) {
		body := "line1\nline2\nline3\n"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, body)
		}))
		defer srv.Close()

		lines, err := fetchTextLines(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"line1", "line2", "line3"}
		if !stringSliceEqual(lines, want) {
			t.Fatalf("got %v, want %v", lines, want)
		}
	})

	t.Run("with blank lines", func(t *testing.T) {
		body := "a\n\nb\n\n\nc\n"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, body)
		}))
		defer srv.Close()

		lines, err := fetchTextLines(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"a", "", "b", "", "", "c"}
		if !stringSliceEqual(lines, want) {
			t.Fatalf("got %v, want %v", lines, want)
		}
	})

	t.Run("http error status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := fetchTextLines(context.Background(), srv.URL)
		if err == nil {
			t.Fatal("expected error for HTTP 404")
		}
	})

	t.Run("server error status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		_, err := fetchTextLines(context.Background(), srv.URL)
		if err == nil {
			t.Fatal("expected error for HTTP 500")
		}
	})

	t.Run("empty body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// No body written
		}))
		defer srv.Close()

		lines, err := fetchTextLines(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(lines) != 0 {
			t.Fatalf("expected 0 lines, got %d: %v", len(lines), lines)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Simulate slow response
			time.Sleep(100 * time.Millisecond)
			fmt.Fprint(w, "data\n")
		}))
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately
		_, err := fetchTextLines(ctx, srv.URL)
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

// ---------------------------------------------------------------------------
// tryAddCandidate
// ---------------------------------------------------------------------------

func TestTryAddCandidate(t *testing.T) {
	newPool := func() *proxyPoolBackend {
		return &proxyPoolBackend{
			pool: make(map[string]*proxyNode),
		}
	}

	t.Run("http url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("http://1.2.3.4:8080")
		if len(b.pool) != 1 {
			t.Fatalf("expected 1 node, got %d", len(b.pool))
		}
		n := b.pool["1.2.3.4:8080"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:8080")
		}
		if n.Proto != "http" {
			t.Fatalf("expected proto http, got %q", n.Proto)
		}
		if n.Addr != "1.2.3.4:8080" {
			t.Fatalf("expected addr 1.2.3.4:8080, got %q", n.Addr)
		}
	})

	t.Run("https url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("https://1.2.3.4:443")
		n := b.pool["1.2.3.4:443"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:443")
		}
		if n.Proto != "https" {
			t.Fatalf("expected proto https, got %q", n.Proto)
		}
	})

	t.Run("socks5 url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("socks5://1.2.3.4:1080")
		n := b.pool["1.2.3.4:1080"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:1080")
		}
		if n.Proto != "socks5" {
			t.Fatalf("expected proto socks5, got %q", n.Proto)
		}
	})

	t.Run("socks4 url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("socks4://1.2.3.4:1080")
		n := b.pool["1.2.3.4:1080"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:1080")
		}
		if n.Proto != "socks4" {
			t.Fatalf("expected proto socks4, got %q", n.Proto)
		}
	})

	t.Run("shadowsocks url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmQ=@1.2.3.4:8388")
		n := b.pool["1.2.3.4:8388"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:8388")
		}
		if n.Proto != "ss" {
			t.Fatalf("expected proto ss, got %q", n.Proto)
		}
	})

	t.Run("trojan url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("trojan://password@1.2.3.4:443")
		n := b.pool["1.2.3.4:443"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:443")
		}
		if n.Proto != "trojan" {
			t.Fatalf("expected proto trojan, got %q", n.Proto)
		}
	})

	t.Run("vless url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("vless://uuid@1.2.3.4:80")
		n := b.pool["1.2.3.4:80"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:80")
		}
		if n.Proto != "vless" {
			t.Fatalf("expected proto vless, got %q", n.Proto)
		}
	})

	t.Run("vmess url", func(t *testing.T) {
		b := newPool()
		v := map[string]interface{}{"add": "1.2.3.4", "port": 443, "id": "uuid"}
		vmessData, _ := json.Marshal(v)
		encoded := base64.StdEncoding.EncodeToString(vmessData)
		b.tryAddCandidate("vmess://" + encoded)
		n := b.pool["1.2.3.4:443"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:443")
		}
		if n.Proto != "vmess" {
			t.Fatalf("expected proto vmess, got %q", n.Proto)
		}
	})

	t.Run("vmess with invalid base64", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("vmess://not-valid-base64!!!")
		if len(b.pool) != 0 {
			t.Fatalf("expected 0 nodes for invalid vmess, got %d", len(b.pool))
		}
	})

	t.Run("hysteria2 url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("hysteria2://password@1.2.3.4:443")
		n := b.pool["1.2.3.4:443"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:443")
		}
		if n.Proto != "hysteria2" {
			t.Fatalf("expected proto hysteria2, got %q", n.Proto)
		}
	})

	t.Run("hy2 url alias", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("hy2://password@1.2.3.4:443")
		n := b.pool["1.2.3.4:443"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:443")
		}
		if n.Proto != "hy2" {
			t.Fatalf("expected proto hy2, got %q", n.Proto)
		}
	})

	t.Run("plain ip port as http", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("1.2.3.4:8080")
		n := b.pool["1.2.3.4:8080"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:8080")
		}
		if n.Proto != "http" {
			t.Fatalf("expected proto http, got %q", n.Proto)
		}
	})

	t.Run("http url without port defaults to 80", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("http://1.2.3.4")
		n := b.pool["1.2.3.4:80"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:80 (default port)")
		}
	})

	t.Run("socks5 without port defaults to 1080", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("socks5://1.2.3.4")
		n := b.pool["1.2.3.4:1080"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:1080 (default port)")
		}
	})

	t.Run("invalid line without scheme", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("invalid-line-without-scheme")
		if len(b.pool) != 0 {
			t.Fatalf("expected 0 nodes for invalid line, got %d", len(b.pool))
		}
	})

	t.Run("duplicate urls not added twice", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("http://1.2.3.4:8080")
		b.tryAddCandidate("http://1.2.3.4:8080") // duplicate
		if len(b.pool) != 1 {
			t.Fatalf("expected 1 node after duplicate, got %d", len(b.pool))
		}
		if len(b.allNodes) != 1 {
			t.Fatalf("expected 1 entry in allNodes, got %d", len(b.allNodes))
		}
	})

	t.Run("duplicate with different scheme different addr", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("http://1.2.3.4:8080")
		b.tryAddCandidate("https://1.2.3.4:8080") // same addr, different scheme
		// only the first one should remain because duplicate detection is by addr
		if len(b.pool) != 1 {
			t.Fatalf("expected 1 node (dedup by addr), got %d", len(b.pool))
		}
		n := b.pool["1.2.3.4:8080"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:8080")
		}
		// The proto should remain as the first one added
		if n.Proto != "http" {
			t.Fatalf("expected proto http (first), got %q", n.Proto)
		}
	})

	t.Run("empty string", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("")
		if len(b.pool) != 0 {
			t.Fatalf("expected 0 nodes for empty string, got %d", len(b.pool))
		}
	})

	t.Run("comment line is still parsed but returns invalid", func(t *testing.T) {
		// Note: tryAddCandidate does not filter comments; the caller
		// (refresh method) skips "#"-prefixed lines before calling.
		// "# foo:1234" is not a valid ip:port, so it should produce 0 nodes.
		b := newPool()
		b.tryAddCandidate("# foo:1234")
		if len(b.pool) != 0 {
			t.Fatalf("expected 0 nodes for comment-like line, got %d", len(b.pool))
		}
	})

	t.Run("tuic url", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("tuic://token@1.2.3.4:1443")
		n := b.pool["1.2.3.4:1443"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:1443")
		}
		if n.Proto != "tuic" {
			t.Fatalf("expected proto tuic, got %q", n.Proto)
		}
	})

	t.Run("http with auth", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("http://user:pass@1.2.3.4:8080")
		n := b.pool["1.2.3.4:8080"]
		if n == nil {
			t.Fatal("expected node at addr 1.2.3.4:8080")
		}
		if n.Proto != "http" {
			t.Fatalf("expected proto http, got %q", n.Proto)
		}
	})

	t.Run("multiple candidates", func(t *testing.T) {
		b := newPool()
		b.tryAddCandidate("http://1.2.3.4:8080")
		b.tryAddCandidate("socks5://5.6.7.8:1080")
		b.tryAddCandidate("https://9.10.11.12:443")
		if len(b.pool) != 3 {
			t.Fatalf("expected 3 nodes, got %d", len(b.pool))
		}
		if b.pool["1.2.3.4:8080"] == nil {
			t.Fatal("missing node 1.2.3.4:8080")
		}
		if b.pool["5.6.7.8:1080"] == nil {
			t.Fatal("missing node 5.6.7.8:1080")
		}
		if b.pool["9.10.11.12:443"] == nil {
			t.Fatal("missing node 9.10.11.12:443")
		}
	})
}

// ---------------------------------------------------------------------------
// checkHTTPConnect
// ---------------------------------------------------------------------------

func TestCheckHTTPConnect(t *testing.T) {
	t.Run("success 200 Connection Established", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		resultCh := make(chan bool, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Read the CONNECT request
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			// Respond with success
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}()

		ok := checkHTTPConnect(context.Background(), ln.Addr().String(), time.Second)
		resultCh <- ok

		if !ok {
			t.Fatal("expected true for valid CONNECT response")
		}
		<-resultCh
	})

	t.Run("success 200 OK", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}()

		ok := checkHTTPConnect(context.Background(), ln.Addr().String(), time.Second)
		if !ok {
			t.Fatal("expected true for 200 OK response")
		}
	})

	t.Run("failure response", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		}()

		ok := checkHTTPConnect(context.Background(), ln.Addr().String(), time.Second)
		if ok {
			t.Fatal("expected false for 403 response")
		}
	})

	t.Run("no server (connection refused)", func(t *testing.T) {
		// Listen on a port and close it, so the port is unused.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		addr := ln.Addr().String()
		ln.Close()

		ok := checkHTTPConnect(context.Background(), addr, time.Second)
		if ok {
			t.Fatal("expected false when connection is refused")
		}
	})

	t.Run("server closes without response", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept but close immediately without sending any response
			conn.Close()
		}()

		ok := checkHTTPConnect(context.Background(), ln.Addr().String(), time.Second)
		if ok {
			t.Fatal("expected false when server closes without response")
		}
	})
}

// ---------------------------------------------------------------------------
// checkSOCKS5Handshake
// ---------------------------------------------------------------------------

func TestCheckSOCKS5Handshake(t *testing.T) {
	t.Run("successful handshake", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Read the client handshake: 0x05 0x01 0x00
			buf := make([]byte, 3)
			_, _ = io.ReadFull(conn, buf)
			// Respond with 0x05 0x00 (SOCKS5, no auth required)
			conn.Write([]byte{0x05, 0x00})
		}()

		ok := checkSOCKS5Handshake(context.Background(), ln.Addr().String(), time.Second)
		if !ok {
			t.Fatal("expected true for valid SOCKS5 handshake")
		}
	})

	t.Run("wrong response version", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 3)
			_, _ = io.ReadFull(conn, buf)
			// Wrong version
			conn.Write([]byte{0x04, 0x00})
		}()

		ok := checkSOCKS5Handshake(context.Background(), ln.Addr().String(), time.Second)
		if ok {
			t.Fatal("expected false for wrong protocol version")
		}
	})

	t.Run("wrong response auth method", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 3)
			_, _ = io.ReadFull(conn, buf)
			// SOCKS5 but auth required (0x05 0x02)
			conn.Write([]byte{0x05, 0x02})
		}()

		ok := checkSOCKS5Handshake(context.Background(), ln.Addr().String(), time.Second)
		if ok {
			t.Fatal("expected false when auth is required (0x02)")
		}
	})

	t.Run("no server (connection refused)", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		addr := ln.Addr().String()
		ln.Close()

		ok := checkSOCKS5Handshake(context.Background(), addr, time.Second)
		if ok {
			t.Fatal("expected false when connection is refused")
		}
	})

	t.Run("server closes without response", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept but close without sending any handshake response
			conn.Close()
		}()

		ok := checkSOCKS5Handshake(context.Background(), ln.Addr().String(), time.Second)
		if ok {
			t.Fatal("expected false when server closes without handshake")
		}
	})

	t.Run("partial response", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 3)
			_, _ = io.ReadFull(conn, buf)
			// Send only 1 byte (instead of 2)
			conn.Write([]byte{0x05})
			conn.Close()
		}()

		ok := checkSOCKS5Handshake(context.Background(), ln.Addr().String(), time.Second)
		if ok {
			t.Fatal("expected false for partial handshake response")
		}
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Benchmark: ensure tryDecodeBase64 is not regressed
// ---------------------------------------------------------------------------

func BenchmarkTryDecodeBase64(b *testing.B) {
	data := base64.StdEncoding.EncodeToString([]byte(`{"add":"1.2.3.4","port":443,"id":"uuid-1234-5678"}`))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tryDecodeBase64(data)
	}
}

func BenchmarkExtractVMessHost(b *testing.B) {
	v := map[string]interface{}{"add": "proxy.example.com", "port": 443, "id": "uuid"}
	vmessData, _ := json.Marshal(v)
	encoded := base64.StdEncoding.EncodeToString(vmessData)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractVMessHost(encoded)
	}
}

