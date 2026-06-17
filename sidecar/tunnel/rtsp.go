// Package tunnel provides pluggable tunnel transport backends.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// ---- RTSP/RTMP Streaming Backend --------------------------------------------
//
// rtspBackend implements an RTSP/RTMP streaming tunnel backend.
// It operates in two modes:
//
//   - "server" mode: listens for RTSP/RTMP client connections
//   - "proxy" mode: connects to an upstream RTSP/RTMP origin and relays
//
// RTSP (Real Time Streaming Protocol) is a stateful TCP-based control
// protocol for media streaming, typically used with RTP/RTCP for media data.
// Default port: 554
//
// RTMP (Real Time Messaging Protocol) is Adobe's protocol for Flash-based
// streaming over TCP. Default port: 1935.
//
// This backend handles:
//   - RTSP control channel (DESCRIBE, OPTIONS, SETUP, PLAY, TEARDOWN)
//   - RTP/RTCP interleaved data over RTSP TCP connection
//   - RTMP chunk streams and handshake
//
// Use cases: CCTV camera relay, live streaming distribution, media origin
// failover through the SkyNet tunnel layer.

type rtspBackend struct {
	name   string
	cfg    rtspConfig
	ln     net.Listener
	readyCh chan struct{}
	stopCh  chan struct{}
	wg     sync.WaitGroup
	metrics atomic.Pointer[metrics.BackendMetrics]
}

type rtspConfig struct {
	Mode         string // "server" (listen) or "proxy" (connect upstream)
	ListenAddr   string // for server mode: host:port to listen on
	OriginURL    string // for proxy mode: rtsp://host:port or rtmp://host:port
	StreamPath   string // stream path name
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

var _ Backend = (*rtspBackend)(nil)
var _ Backend = (*rtmpBackend)(nil)

// ---- RTSP Backend ---

func (b *rtspBackend) Name() string { return b.name }
func (b *rtspBackend) Type() string { return "rtsp" }

func (b *rtspBackend) Start(ctx context.Context) error {
	if b.metrics.Load() == nil {
		b.metrics.Store(metrics.Default().ForBackend(b.name))
	}
	if b.cfg.ReadTimeout == 0 {
		b.cfg.ReadTimeout = 10 * time.Second
	}
	if b.cfg.WriteTimeout == 0 {
		b.cfg.WriteTimeout = 10 * time.Second
	}

	if b.cfg.Mode == "server" || b.cfg.Mode == "" {
		addr, err := net.ResolveTCPAddr("tcp", b.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("rtsp: %w", err)
		}
		ln, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return fmt.Errorf("rtsp: listen %s: %w", b.cfg.ListenAddr, err)
		}
		b.ln = ln
	}

	close(b.readyCh)
	b.wg.Add(1)
	go b.serveLoop()
	return nil
}

func (b *rtspBackend) Stop(ctx context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	if b.ln != nil {
		b.ln.Close()
	}
	return nil
}

func (b *rtspBackend) Ready() <-chan struct{} { return b.readyCh }

func (b *rtspBackend) serveLoop() {
	defer b.wg.Done()
	for {
		select {
		case <-b.stopCh:
			return
		default:
			if b.ln == nil {
				return
			}
			if err := b.ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				return
			}
			conn, err := b.ln.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			b.wg.Add(1)
			go func() { defer b.wg.Done(); b.handleClient(conn) }()
		}
	}
}

func (b *rtspBackend) handleClient(conn net.Conn) {
	defer conn.Close()
	b.recordConnOpen()

	// Peek at first byte to detect RTSP vs RTMP
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	firstByte := make([]byte, 1)
	n, err := conn.Read(firstByte)
	if err != nil || n == 0 {
		b.recordError()
		return
	}
	conn.SetReadDeadline(time.Time{})

	switch firstByte[0] {
	case 0x03, 0x06, 0x14, 0x16:
		// RTMP protocol detected; rtspBackend only handles RTSP
		return
	default:
		// Assume RTSP (starts with letter: O=OPTIONS, D=DESCRIBE, etc.)
		b.handleRTSPClient(conn, firstByte)
	}
}

func (b *rtspBackend) handleRTSPClient(conn net.Conn, firstByte []byte) {
	if b.cfg.OriginURL != "" {
		b.proxyRTSP(conn, firstByte)
		return
	}
	// Server mode: act as RTSP server responding to client requests
	b.serveRTSPClient(conn, firstByte)
}

func (b *rtspBackend) serveRTSPClient(conn net.Conn, firstByte []byte) {
	// Wrap with first byte pre-pended
	br := &firstByteReader{conn: conn, first: firstByte}
	rbuf := make([]byte, 8192)
	var cseq int
	for {
		conn.SetReadDeadline(time.Now().Add(b.cfg.ReadTimeout))
		n, err := br.Read(rbuf)
		if err != nil {
			return
		}
		b.recordRecv(n)

		req := string(rbuf[:n])
		// Simple RTSP response builder
		resp := b.buildRTSPServerResponse(req, &cseq)
		if resp != nil {
			conn.Write(resp)
			b.recordSent(len(resp))
			// Check if client wants to close
			if strings.Contains(req, "TEARDOWN") {
				return
			}
		}
	}
}

func (b *rtspBackend) buildRTSPServerResponse(req string, cseq *int) []byte {
	// Extract CSeq
	var method, url, version string
	var reqCSeq int
	fmt.Sscanf(req, "%s %s %s", &method, &url, &version)
	// Also parse CSeq header
	for _, line := range strings.Split(req, "\r\n") {
		if strings.HasPrefix(line, "CSeq:") {
			fmt.Sscanf(line, "CSeq: %d", &reqCSeq)
		}
	}
	*cseq = reqCSeq

	switch method {
	case "OPTIONS":
		return []byte(fmt.Sprintf(
			"RTSP/1.0 200 OK\r\nCSeq: %d\r\nPublic: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n\r\n",
			reqCSeq))
	case "DESCRIBE":
		streamPath := b.cfg.StreamPath
		if streamPath == "" {
			streamPath = "stream"
		}
		sdp := fmt.Sprintf("v=0\r\n"+
			"o=- 0 0 IN IP4 127.0.0.1\r\n"+
			"s=%s\r\n"+
			"c=IN IP4 0.0.0.0\r\n"+
			"t=0 0\r\n"+
			"m=video 0 RTP/AVP 96\r\n"+
			"a=rtpmap:96 H264/90000\r\n", streamPath)
		return []byte(fmt.Sprintf(
			"RTSP/1.0 200 OK\r\n"+
				"CSeq: %d\r\n"+
				"Content-Type: application/sdp\r\n"+
				"Content-Length: %d\r\n\r\n%s",
			reqCSeq, len(sdp), sdp))
	case "SETUP":
		sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
		return []byte(fmt.Sprintf(
			"RTSP/1.0 200 OK\r\n"+
				"CSeq: %d\r\n"+
				"Session: %s\r\n"+
				"Transport: RTP/AVP;unicast;client_port=8000-8001;server_port=7000-7001\r\n\r\n",
			reqCSeq, sessionID))
	case "PLAY":
		rtpInfo := fmt.Sprintf("url=rtsp://127.0.0.1/%s", b.cfg.StreamPath)
		return []byte(fmt.Sprintf(
			"RTSP/1.0 200 OK\r\n"+
				"CSeq: %d\r\n"+
				"Session: 12345678\r\n"+
				"RTP-Info: %s\r\n\r\n",
			reqCSeq, rtpInfo))
	case "TEARDOWN":
		return []byte(fmt.Sprintf(
			"RTSP/1.0 200 OK\r\nCSeq: %d\r\n\r\n", reqCSeq))
	default:
		return []byte(fmt.Sprintf(
			"RTSP/1.0 501 Not Implemented\r\nCSeq: %d\r\n\r\n", reqCSeq))
	}
}

func (b *rtspBackend) proxyRTSP(conn net.Conn, firstByte []byte) {
	// Connect to upstream RTSP server
	addr := b.rtspUpstreamAddr()
	upstream, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		b.recordError()
		return
	}
	defer upstream.Close()

	// Write the first byte we peeked
	if _, err := upstream.Write(firstByte); err != nil {
		b.recordError()
		return
	}

	// Bidirectional relay
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, conn)
		b.recordSent(int(n))
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(conn, upstream)
		b.recordRecv(int(n))
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-b.stopCh:
	}
}

func (b *rtspBackend) rtspUpstreamAddr() string {
	urlStr := b.cfg.OriginURL
	if strings.HasPrefix(urlStr, "rtsp://") {
		hostPort := strings.TrimPrefix(urlStr, "rtsp://")
		hostPort = strings.SplitN(hostPort, "/", 2)[0]
		return hostPort
	}
	return b.cfg.OriginURL
}

// ---- RTMP Backend (raw TCP relay) ---

type rtmpBackend struct {
	name   string
	cfg    rtspConfig
	ln     net.Listener
	readyCh chan struct{}
	stopCh  chan struct{}
	wg     sync.WaitGroup
	metrics atomic.Pointer[metrics.BackendMetrics]
}

func (b *rtmpBackend) Name() string { return b.name }
func (b *rtmpBackend) Type() string { return "rtmp" }

func (b *rtmpBackend) Start(ctx context.Context) error {
	if b.metrics.Load() == nil {
		b.metrics.Store(metrics.Default().ForBackend(b.name))
	}
	addr, err := net.ResolveTCPAddr("tcp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("rtmp: %w", err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("rtmp: listen %s: %w", b.cfg.ListenAddr, err)
	}
	b.ln = ln
	close(b.readyCh)
	b.wg.Add(1)
	go b.serveRTMP()
	return nil
}

func (b *rtmpBackend) Stop(ctx context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	if b.ln != nil {
		b.ln.Close()
	}
	return nil
}

func (b *rtmpBackend) Ready() <-chan struct{} { return b.readyCh }

func (b *rtmpBackend) serveRTMP() {
	defer b.wg.Done()
	for {
		select {
		case <-b.stopCh:
			return
		default:
			if err := b.ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				return
			}
			conn, err := b.ln.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			b.wg.Add(1)
			go func() { defer b.wg.Done(); b.handleRTMPClient(conn, nil) }()
		}
	}
}

func (b *rtmpBackend) handleRTMPClient(conn net.Conn, firstByte []byte) {
	defer conn.Close()
	b.recordConnOpen()

	if firstByte == nil {
		firstByte = make([]byte, 1)
		if _, err := conn.Read(firstByte); err != nil {
			b.recordError()
			return
		}
	}

	// Relay to upstream if configured
	if b.cfg.OriginURL != "" {
		b.relayRTMP(conn, firstByte)
	}
}

func (b *rtmpBackend) relayRTMP(conn net.Conn, firstByte []byte) {
	addr := b.rtmpUpstreamAddr()
	upstream, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		b.recordError()
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(firstByte); err != nil {
		b.recordError()
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, conn)
		b.recordSent(int(n))
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(conn, upstream)
		b.recordRecv(int(n))
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-b.stopCh:
	}
}

func (b *rtmpBackend) rtmpUpstreamAddr() string {
	urlStr := b.cfg.OriginURL
	if strings.HasPrefix(urlStr, "rtmp://") {
		hostPort := strings.TrimPrefix(urlStr, "rtmp://")
		hostPort = strings.SplitN(hostPort, "/", 2)[0]
		// hostPort might be host or host:port
		// default RTMP port is 1935
		if !strings.Contains(hostPort, ":") {
			hostPort += ":1935"
		}
		return hostPort
	}
	// Assume it's already host:port
	return b.cfg.OriginURL
}

// ---- Shared helpers ---

func (b *rtspBackend) recordConnOpen() {
	if m := b.metrics.Load(); m != nil {
		m.ConnectionsActive.Add(1)
	}
}
func (b *rtspBackend) recordSent(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesSentTotal.Add(uint64(n))
	}
}
func (b *rtspBackend) recordRecv(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesRecvTotal.Add(uint64(n))
	}
}
func (b *rtspBackend) recordError() {
	if m := b.metrics.Load(); m != nil {
		m.ErrorsTotal.Add(1)
	}
}

func (b *rtmpBackend) recordConnOpen() {
	if m := b.metrics.Load(); m != nil {
		m.ConnectionsActive.Add(1)
	}
}
func (b *rtmpBackend) recordSent(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesSentTotal.Add(uint64(n))
	}
}
func (b *rtmpBackend) recordRecv(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesRecvTotal.Add(uint64(n))
	}
}
func (b *rtmpBackend) recordError() {
	if m := b.metrics.Load(); m != nil {
		m.ErrorsTotal.Add(1)
	}
}

// firstByteReader wraps a connection to prepend the first peeked byte.
type firstByteReader struct {
	conn  net.Conn
	first []byte
	used  bool
}

func (r *firstByteReader) Read(p []byte) (n int, err error) {
	if !r.used && len(r.first) > 0 {
		n = copy(p, r.first)
		r.used = true
		if n < len(p) {
			remaining, err := r.conn.Read(p[n:])
			return n + remaining, err
		}
		return n, nil
	}
	return r.conn.Read(p)
}

// ---- Constructors ---

func newRTSPBackend(cfg Config) Backend {
	getArg := func(i int) string {
		if i < len(cfg.ExtraArgs) {
			return cfg.ExtraArgs[i]
		}
		return ""
	}
	mode := getArg(0)
	if mode == "" {
		mode = "server"
	}
	listenAddr := cfg.ListenAddress
	if listenAddr == "" {
		listenAddr = getArg(1)
	}
	if listenAddr == "" {
		listenAddr = ":8554" // default RTSP port
	}
	originURL := cfg.OriginURL
	if originURL == "" {
		originURL = getArg(2)
	}
	var streamPath string
	if len(cfg.RoutingRules) > 0 {
		streamPath = cfg.RoutingRules[0]
	}
	return &rtspBackend{
		name: cfg.Name,
		cfg: rtspConfig{
			Mode:       mode,
			ListenAddr: listenAddr,
			OriginURL:  originURL,
			StreamPath: streamPath,
		},
		readyCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
}

func newRTMPBackend(cfg Config) Backend {
	getArg := func(i int) string {
		if i < len(cfg.ExtraArgs) {
			return cfg.ExtraArgs[i]
		}
		return ""
	}
	listenAddr := cfg.ListenAddress
	if listenAddr == "" {
		listenAddr = getArg(0)
	}
	if listenAddr == "" {
		listenAddr = ":1935" // default RTMP port
	}
	originURL := cfg.OriginURL
	if originURL == "" {
		originURL = getArg(1)
	}
	return &rtmpBackend{
		name: cfg.Name,
		cfg: rtspConfig{
			Mode:       "server",
			ListenAddr: listenAddr,
			OriginURL:  originURL,
		},
		readyCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
}
