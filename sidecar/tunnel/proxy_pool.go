package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// ---------------------------------------------------------------------------
// proxyPoolBackend — automatically discovers, validates and pools free proxy
// nodes from public subscription sources (e.g. gfpcom/free-proxy-list).
//
// It serves two purposes:
//   1. **Proxy source** — other backends (failover, smart-router) can query it
//      for healthy endpoints and route traffic through them.
//   2. **Standalone HTTP proxy** — if ProxyAddr is configured, the pool starts
//      a local HTTP proxy that randomly picks healthy nodes for each outgoing
//      request. This lets users configure their browser/OS to use the pool as
//      a plain HTTP proxy without any extra tooling.
//
// Lifecycle:
//   Init()   — configure subscription URLs and pool parameters.
//   Start()  — perform initial fetch+validate, then run background refreshes.
//   Ready()  — closes as soon as at least one proxy is available.
//   Stop()   — shuts down the background goroutines and local proxy listener.
// ---------------------------------------------------------------------------

// DefaultProxyPoolSubscriptionURLs are the gfpcom/free-proxy-list wiki raw
// links used when no explicit subscription list is provided.
var DefaultProxyPoolSubscriptionURLs = []string{
	// gfpcom — 纯文本 HTTP/HTTPS/SOCKS 格式，量最大
	"https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt",
	"https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt",
	"https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt",
	"https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt",
	// barabama/freenodes — v2ray/clash 订阅格式，含 SS/VMess/VLESS/Trojan/Hysteria2
	"https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/simple.txt",
	"https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.txt",
	"https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodefree.txt",
	"https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodev2ray.txt",
	"https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/v2rayshare.txt",
	"https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/wenode.txt",
	"https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/ndnode.txt",
	// caijh/FreeProxiesScraper — 每行 base64 编码的 SS/VMess/Trojan 订阅
	"https://raw.githubusercontent.com/caijh/FreeProxiesScraper/master/Eternity",
}

// proxyPoolBackend maintains a dynamically-refreshed pool of free proxies.
type proxyPoolBackend struct {
	cfg Config

	mu           sync.Mutex
	subscription []string         // proxy list download URLs
	pool         map[string]*proxyNode // addr → node (healthy only)
	allNodes     []*proxyNode     // all nodes ever discovered (for iteration)
	ready        chan struct{}
	started      bool
	stopped      bool
	cancel       context.CancelFunc

	// local HTTP proxy
	proxyListener net.Listener
	proxyServer   *http.Server

	// stats
	totalFetched  uint64
	totalValid    uint64
	totalExpired  uint64
}

// fetchClient is a dedicated HTTP client with sane timeouts for
// fetching subscription lists. Avoids http.DefaultClient which
// has no timeout at all.
var fetchClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
	},
}

// proxyNode represents one proxy endpoint with its health state.
type proxyNode struct {
	Addr    string // "ip:port"
	Proto   string // "http", "https", "socks5", "socks4"
	AliveAt int64  // unix nano of last successful health check
	Latency time.Duration
}

func newProxyPoolBackend(cfg Config) *proxyPoolBackend {
	subs := DefaultProxyPoolSubscriptionURLs
	if len(cfg.Servers) > 0 {
		// If user-provided subscription URLs exist, use them instead.
		subs = cfg.Servers
	}
	return &proxyPoolBackend{
		cfg:          cfg,
		subscription: subs,
		pool:         make(map[string]*proxyNode),
		ready:        make(chan struct{}),
	}
}

func (b *proxyPoolBackend) Name() string             { return "proxy-pool://" + b.cfg.Name }
func (b *proxyPoolBackend) Type() string              { return TypeProxyPool }
func (b *proxyPoolBackend) Ready() <-chan struct{}    { return b.ready }

// Start launches the proxy pool: initial fetch + background refresher.
func (b *proxyPoolBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}
	b.started = true
	childCtx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	b.mu.Unlock()

	metrics.SetAvailable(TypeProxyPool, false)

	// Phase 1: initial fetch (blocking, with a sensible timeout).
	fetchCtx, fetchCancel := context.WithTimeout(childCtx, 30*time.Second)
	b.refresh(fetchCtx)
	fetchCancel()

	// Phase 2: background periodic refresh.
	go b.refreshLoop(childCtx)

	// Phase 3: start local HTTP proxy if configured.
	if b.cfg.ProxyListen != "" {
		go b.serveLocalProxy(childCtx)
	}

	// Signal ready if we have at least one healthy proxy.
	if len(b.pool) > 0 {
		b.mu.Lock()
		select {
		case <-b.ready:
		default:
			close(b.ready)
		}
		metrics.SetAvailable(TypeProxyPool, true)
		b.mu.Unlock()
	}

	return nil
}

// refreshLoop re-fetches and re-validates the proxy pool periodically.
func (b *proxyPoolBackend) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	healthTicker := time.NewTicker(2 * time.Minute)
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.refresh(ctx)
		case <-healthTicker.C:
			b.pruneDead(ctx)
		}
	}
}

// refresh fetches all subscription URLs and validates discovered proxies.
func (b *proxyPoolBackend) refresh(ctx context.Context) {
	b.mu.Lock()
	subs := make([]string, len(b.subscription))
	copy(subs, b.subscription)
	b.mu.Unlock()

	var fetched int
	for _, subURL := range subs {
		lines, err := fetchTextLines(ctx, subURL)
		if err != nil {
			continue
		}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fetched++
			// If line looks like base64 (no ://), try decoding.
			if !strings.Contains(line, "://") {
				if decoded, err := tryDecodeBase64(line); err == nil {
					// Decoded string may be a proxy URL — try it.
					b.tryAddCandidate(decoded)
				} else {
					b.tryAddCandidate(line)
				}
			} else {
				b.tryAddCandidate(line)
			}
		}
	}
	atomic.AddUint64(&b.totalFetched, uint64(fetched))

	// Re-validate all candidates.
	b.validateAll(ctx)

	b.mu.Lock()
	n := len(b.pool)
	b.mu.Unlock()

	// If we gained any healthy proxy and ready is not yet closed, close it.
	if n > 0 {
		b.mu.Lock()
		select {
		case <-b.ready:
		default:
			close(b.ready)
		}
		metrics.SetAvailable(TypeProxyPool, true)
		b.mu.Unlock()
	}
}

// tryAddCandidate parses a single line from a subscription list and adds it
// as a candidate node (not yet validated). Supported formats:
//
//   http://ip:port                          HTTP proxy
//   http://user:pass@ip:port                HTTP proxy with auth
//   https://ip:port                         HTTPS proxy
//   socks5://ip:port                        SOCKS5 proxy
//   socks4://ip:port                        SOCKS4 proxy
//   ss://method:pass@ip:port#tag            Shadowsocks
//   trojan://pass@ip:port?query#tag         Trojan
//   vless://uuid@ip:port?query#tag          VLess
//   vmess://base64(json)                    VMess (host:port extracted from JSON)
//   hysteria2://pass@ip:port?query#tag      Hysteria2
//   ip:port                                 → treated as HTTP
func (b *proxyPoolBackend) tryAddCandidate(line string) {
	var addr, proto string

	// Try parsing as URL first.
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil {
			return
		}
		switch u.Scheme {
		case "http", "https":
			proto = u.Scheme
			addr = u.Host
			if u.Port() == "" {
				addr = u.Host + ":80"
			}
		case "socks5":
			proto = u.Scheme
			addr = u.Host
			if u.Port() == "" {
				addr = u.Host + ":1080"
			}
		case "socks4":
			proto = u.Scheme
			addr = u.Host
			if u.Port() == "" {
				addr = u.Host + ":1080"
			}
		case "ss", "trojan", "vless", "hysteria2", "hy2":
			// These protocols use user@host:port format.
			// url.Parse places "user:pass" in u.User and host:port in u.Host.
			proto = u.Scheme
			addr = u.Host // already host:port after stripping userinfo
			if u.Port() == "" {
				addr = u.Host
			}
		case "vmess":
			// vmess://base64encodedJSON — no host in URL directly.
			// Try to parse the base64 JSON to extract host:port.
			proto = u.Scheme
			addr = extractVMessHost(u.Host)
			if addr == "" {
				return
			}
		case "tuic":
			proto = u.Scheme
			addr = u.Host
		default:
			// Unknown scheme — try to extract host:port anyway.
			if h, _, err := net.SplitHostPort(u.Host); err == nil && h != "" {
				proto = u.Scheme
				addr = u.Host
			}
			return
		}
	} else {
		// Plain "ip:port" — treat as HTTP.
		// Reject lines that look like comments (starting with #) or
		// lines that don't pass SplitHostPort.
		if strings.HasPrefix(line, "#") {
			return
		}
		_, _, err := net.SplitHostPort(line)
		if err != nil {
			return
		}
		addr = line
		proto = "http"
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Skip duplicates.
	if _, exists := b.pool[addr]; exists {
		return
	}

	node := &proxyNode{
		Addr:  addr,
		Proto: proto,
	}
	b.pool[addr] = node
	b.allNodes = append(b.allNodes, node)
}

// extractVMessHost attempts to extract host:port from a vmess:// base64 URL.
// The path portion is base64-encoded JSON: {"add":"host","port":443,...}
func extractVMessHost(raw string) string {
	// vmess:// may be followed by base64 directly (no @ separator).
	// Try to decode and parse the JSON.
	decoded, err := tryDecodeBase64(raw)
	if err != nil {
		return ""
	}
	var v struct {
		Add  string `json:"add"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return ""
	}
	if v.Add == "" || v.Port == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", v.Add, v.Port)
}

// tryDecodeBase64 attempts base64 decoding (standard and URL-safe variants).
func tryDecodeBase64(s string) (string, error) {
	// Try standard base64.
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), nil
	}
	// Try URL-safe base64.
	decoded, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), nil
	}
	// Try with padding fix.
	missing := len(s) % 4
	if missing > 0 {
		s += string("===="[:4-missing])
	}
	decoded, err = base64.StdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), nil
	}
	decoded, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), nil
	}
	return "", fmt.Errorf("base64 decode failed")
}

// validateAll runs TCP health checks on all candidate nodes.
func (b *proxyPoolBackend) validateAll(ctx context.Context) {
	b.mu.Lock()
	nodes := make([]*proxyNode, 0, len(b.pool))
	for _, n := range b.pool {
		nodes = append(nodes, n)
	}
	b.mu.Unlock()

	if len(nodes) == 0 {
		return
	}

	// Use a semaphore to limit concurrent checks.
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var validCount int64

	for _, node := range nodes {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(n *proxyNode) {
			defer wg.Done()
			defer func() { <-sem }()
			if b.checkAlive(ctx, n) {
				atomic.AddInt64(&validCount, 1)
			}
		}(node)
	}
	wg.Wait()

	// Remove dead nodes from pool.
	b.mu.Lock()
	for _, n := range nodes {
		if atomic.LoadInt64(&n.AliveAt) == 0 {
			delete(b.pool, n.Addr)
		}
	}
	atomic.StoreUint64(&b.totalValid, uint64(len(b.pool)))
	b.mu.Unlock()
}

// checkAlive performs a protocol-appropriate health check on a proxy node.
// For HTTP/HTTPS: sends a CONNECT request and checks for a valid response.
// For SOCKS5: performs a SOCKS5 handshake.
// For Trojan: performs a TLS handshake (Trojan always uses TLS).
// For all other protocols: falls back to TCP connectivity test.
func (b *proxyPoolBackend) checkAlive(ctx context.Context, node *proxyNode) bool {
	start := time.Now()

	switch node.Proto {
	case "http", "https":
		ok := checkHTTPConnect(ctx, node.Addr, 5*time.Second)
		if !ok {
			return false
		}
	case "socks5":
		ok := checkSOCKS5Handshake(ctx, node.Addr, 5*time.Second)
		if !ok {
			return false
		}
	case "trojan":
		// Trojan always wraps in TLS. Verify the server speaks TLS.
		ok := checkTLSHandshake(ctx, node.Addr, 5*time.Second)
		if !ok {
			return false
		}
	default:
		// SS / VMess / VLess / SOCKS4 / others:
		// We can't do full protocol verification without importing their
		// client libraries, so TCP ping is the best we can do.
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", node.Addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
	}

	latency := time.Since(start)
	atomic.StoreInt64(&node.AliveAt, start.UnixNano())
	node.Latency = latency
	return true
}

// checkHTTPConnect tests whether addr responds to an HTTP CONNECT request.
// This is the standard way to verify an HTTP proxy is functional.
func checkHTTPConnect(ctx context.Context, addr string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send CONNECT to a well-known host (cloudflare.com on 443).
	req := "CONNECT cloudflare.com:443 HTTP/1.1\r\nHost: cloudflare.com:443\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}

	// Read response — expect "HTTP/1.1 200 Connection Established".
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	resp := string(buf[:n])
	return strings.Contains(resp, "200 Connection Established") ||
		strings.Contains(resp, "200 OK")
}

// checkSOCKS5Handshake performs a standard SOCKS5 handshake with no auth
// (0x05 0x01 0x00) and checks for 0x05 0x00 response.
func checkSOCKS5Handshake(ctx context.Context, addr string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 handshake: client sends 0x05 0x01 0x00 (SOCKS5, 1 auth method, no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}

	// Server should respond 0x05 0x00 (SOCKS5, no auth required).
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	return resp[0] == 0x05 && resp[1] == 0x00
}

// checkTLSHandshake verifies that the server at addr completes a TLS handshake.
// This confirms the server speaks TLS — a reasonable validation for Trojan
// proxies (Trojan always runs over TLS).
func checkTLSHandshake(ctx context.Context, addr string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // we only care about TLS handshake, not cert validity
	})
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	_ = tlsConn.Close()
	return true
}

// pruneDead re-tests all pool members and removes the ones that went dark.
func (b *proxyPoolBackend) pruneDead(ctx context.Context) {
	b.mu.Lock()
	nodes := make([]*proxyNode, 0, len(b.pool))
	for _, n := range b.pool {
		nodes = append(nodes, n)
	}
	b.mu.Unlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	var deadCount int64

	for _, node := range nodes {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(n *proxyNode) {
			defer wg.Done()
			defer func() { <-sem }()
			if !b.checkAlive(ctx, n) {
				atomic.StoreInt64(&n.AliveAt, 0)
				atomic.AddInt64(&deadCount, 1)
			}
		}(node)
	}
	wg.Wait()

	b.mu.Lock()
	for _, n := range nodes {
		if atomic.LoadInt64(&n.AliveAt) == 0 {
			delete(b.pool, n.Addr)
		}
	}
	atomic.AddUint64(&b.totalExpired, uint64(deadCount))
	alive := len(b.pool)
	if alive == 0 {
		metrics.SetAvailable(TypeProxyPool, false)
	}
	b.mu.Unlock()
}

// HealthyProxy returns the lowest-latency healthy proxy address, or "" if none.
// Selection is O(n) on pool size — fine for our typical pool sizes (hundreds to
// low thousands). For larger pools consider a min-heap.
func (b *proxyPoolBackend) HealthyProxy() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pool) == 0 {
		return ""
	}
	var best string
	var bestLatency time.Duration
	first := true
	for _, n := range b.pool {
		if first || n.Latency < bestLatency {
			best = n.Addr
			bestLatency = n.Latency
			first = false
		}
	}
	return best
}

// HealthyProxies returns all currently healthy proxy addresses, sorted by
// latency (fastest first).
func (b *proxyPoolBackend) HealthyProxies() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	nodes := make([]*proxyNode, 0, len(b.pool))
	for _, n := range b.pool {
		nodes = append(nodes, n)
	}
	// Sort by latency ascending.
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if nodes[j].Latency < nodes[i].Latency {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			}
		}
	}
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = fmt.Sprintf("%s://%s (%.0fms)", n.Proto, n.Addr, float64(n.Latency)/float64(time.Millisecond))
	}
	return out
}

// ProxyAddr returns the local HTTP proxy listener address, or "" if not started.
func (b *proxyPoolBackend) ProxyAddr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.proxyListener == nil {
		return ""
	}
	return b.proxyListener.Addr().String()
}

// -------- Local HTTP proxy (routes through pool) ---------------------------

// serveLocalProxy starts a local HTTP proxy that forwards each request through
// a randomly-chosen healthy free proxy.
func (b *proxyPoolBackend) serveLocalProxy(ctx context.Context) {
	addr := b.cfg.ProxyListen
	if addr == "" {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", b.handleProxyWriter)

	b.mu.Lock()
	b.proxyServer = &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		b.mu.Unlock()
		metrics.RecordError(TypeProxyPool)
		return
	}
	b.proxyListener = ln
	b.mu.Unlock()

	metrics.SetAvailable(TypeProxyPool+"-proxy", true)

	// Serve in a goroutine; shut down when context is cancelled.
	go func() {
		_ = b.proxyServer.Serve(ln)
	}()

	<-ctx.Done()
	_ = b.proxyServer.Close()
	if ln != nil {
		_ = ln.Close()
	}
	metrics.SetAvailable(TypeProxyPool+"-proxy", false)
}

// handleProxyWriter implements a simple HTTP forward proxy using the pool.
func (b *proxyPoolBackend) handleProxyWriter(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// HTTPS CONNECT tunnel.
		b.handleConnect(w, r)
		return
	}

	// Plain HTTP proxy.
	proxyAddr := b.HealthyProxy()
	if proxyAddr == "" {
		http.Error(w, "no healthy proxy in pool", http.StatusServiceUnavailable)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Copy headers.
	for k, vs := range r.Header {
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		metrics.RecordError(TypeProxyPool)
		http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	metrics.RecordTransfer(TypeProxyPool, 0, resp.ContentLength)
}

// handleConnect handles HTTPS CONNECT via a healthy pool proxy.
func (b *proxyPoolBackend) handleConnect(w http.ResponseWriter, r *http.Request) {
	proxyAddr := b.HealthyProxy()
	if proxyAddr == "" {
		http.Error(w, "no healthy proxy", http.StatusServiceUnavailable)
		return
	}

	destConn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		http.Error(w, "proxy connect failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = destConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 to client.
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { _, _ = io.Copy(destConn, clientConn); wg.Done() }()
	go func() { _, _ = io.Copy(clientConn, destConn); wg.Done() }()
	wg.Wait()
	_ = clientConn.Close()
	_ = destConn.Close()
}

// -------- Standalone helpers -----------------------------------------------

// fetchTextLines downloads a URL and returns non-empty lines.
func fetchTextLines(ctx context.Context, rawURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SkyNet-SSI-ProxyPool/1.0")

	resp, err := fetchClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", rawURL, resp.StatusCode)
	}

	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// -------- Stats / status helpers -------------------------------------------

// PoolStats returns a snapshot of the proxy pool for dashboard / IPC.
func (b *proxyPoolBackend) PoolStats() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()

	alive := len(b.pool)
	protos := make(map[string]int)
	var totalLatency time.Duration
	var minLatency time.Duration
	var maxLatency time.Duration
	first := true
	for _, n := range b.pool {
		protos[n.Proto]++
		totalLatency += n.Latency
		if first || n.Latency < minLatency {
			minLatency = n.Latency
		}
		if first || n.Latency > maxLatency {
			maxLatency = n.Latency
		}
		first = false
	}
	avgLatency := time.Duration(0)
	if alive > 0 {
		avgLatency = totalLatency / time.Duration(alive)
	}

	return map[string]any{
		"alive":         alive,
		"total_fetched":  atomic.LoadUint64(&b.totalFetched),
		"total_valid":    atomic.LoadUint64(&b.totalValid),
		"total_expired":  atomic.LoadUint64(&b.totalExpired),
		"protocols":     protos,
		"by_protocol":   protos,
		"latency_ms": map[string]float64{
			"min": float64(minLatency) / float64(time.Millisecond),
			"avg": float64(avgLatency) / float64(time.Millisecond),
			"max": float64(maxLatency) / float64(time.Millisecond),
		},
		"subscription_urls": b.subscription,
		"proxy_listen":     b.cfg.ProxyListen,
	}
}

// -------- Stop -------------------------------------------------------------

func (b *proxyPoolBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
	}
	if b.proxyListener != nil {
		_ = b.proxyListener.Close()
	}
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{}) // reset for next Start()
	b.mu.Unlock()

	metrics.SetAvailable(TypeProxyPool, false)
	metrics.SetAvailable(TypeProxyPool+"-proxy", false)
	return nil
}
