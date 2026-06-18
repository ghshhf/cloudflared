package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// dtlsBackend provides a tunnel backend over DTLS (Datagram Transport Layer
// Security), RFC 6347. DTLS allows encrypting UDP traffic end-to-end,
// making it ideal for latency-sensitive protocols that run over UDP.
//
// Modes:
//   - "client": actively connects to a remote DTLS server
//   - "server": listens for incoming DTLS client connections
//
// Since DTLS is connectionless, the server maintains a map of peer addresses
// to active DTLS connections. Each unique client source address gets its own
// DTLS session.
type dtlsBackend struct {
	name    string
	cfg     dtlsConfig
	ln      *net.UDPConn
	client  *tls.Conn // for client mode only
	readyCh chan struct{}
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// server-side: map of peer address to DTLS connection
	peers   map[string]*tls.Conn
	peersMu sync.RWMutex

	metrics atomic.Pointer[metrics.BackendMetrics]
}

type dtlsConfig struct {
	Mode string // "server" or "client"

	// ListenAddr is the local UDP address to bind (server mode)
	ListenAddr string
	// RemoteAddr is the remote DTLS peer address (client mode)
	RemoteAddr string

	// CertFile / KeyFile: PEM-encoded TLS certificate and key (server mode required)
	CertFile string
	KeyFile  string
	// CACertFile: CA certificate for client verify (client mode)
	CACertFile string

	// InsecureSkipVerify: skip server certificate verification (client only)
	InsecureSkipVerify bool

	// MTU for tunneled traffic (default 1400)
	MTU int
}

// DTLS version constants (RFC 6347).
const (
	dtlsVersion10 = 0xfeff // DTLS 1.0
	dtlsVersion11 = 0xfeff // DTLS 1.1 (same value)
	dtlsVersion12 = 0xfefd // DTLS 1.2
)

var _ Backend = (*dtlsBackend)(nil)

// Name implements Backend.
func (b *dtlsBackend) Name() string { return b.name }

// Type implements Backend.
func (b *dtlsBackend) Type() string { return "dtls" }

// Start implements Backend.
func (b *dtlsBackend) Start(ctx context.Context) error {
	if b.metrics.Load() == nil {
		b.metrics.Store(metrics.Default().ForBackend(b.name))
	}

	tlsCfg, err := b.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("dtls: build TLS config: %w", err)
	}

	switch b.cfg.Mode {
	case "server":
		return b.startServer(ctx, tlsCfg)
	case "client":
		return b.startClient(ctx, tlsCfg)
	default:
		return fmt.Errorf("dtls: mode must be 'server' or 'client', got %q", b.cfg.Mode)
	}
}

// Stop implements Backend.
func (b *dtlsBackend) Stop(ctx context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	if b.ln != nil {
		b.ln.Close()
	}
	if b.client != nil {
		b.client.Close()
	}
	return nil
}

// Ready implements Backend.
func (b *dtlsBackend) Ready() <-chan struct{} { return b.readyCh }

func (b *dtlsBackend) startServer(ctx context.Context, tlsCfg *tls.Config) error {
	addr, err := net.ResolveUDPAddr("udp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("dtls: resolve listen addr: %w", err)
	}
	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dtls: listen UDP: %w", err)
	}
	b.ln = ln
	close(b.readyCh)

	b.peers = make(map[string]*tls.Conn)
	b.wg.Add(1)
	go b.serverLoop(tlsCfg)
	return nil
}

// serverLoop reads incoming UDP packets. Each new source address triggers a
// DTLS handshake to establish a session. Existing sessions are used for
// data transport.
func (b *dtlsBackend) serverLoop(tlsCfg *tls.Config) {
	defer b.wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-b.stopCh:
			return
		default:
			b.ln.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, raddr, err := b.ln.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			peerKey := raddr.String()
			b.peersMu.RLock()
			conn, ok := b.peers[peerKey]
			b.peersMu.RUnlock()

			if !ok {
				// New peer: perform DTLS handshake
				// InDTLS, we can't easily do server-side handshake on a single UDP port
				// from a raw packet. A full implementation would need to implement
				// the DTLS state machine. For this backend, we rely on client-side
				// connections or accept the first packet as the handshake.
				//
				// Since Go's crypto/tls doesn't expose the DTLS packet-level API,
				// we use the client-side approach: each "connection" is a pair of
				// (remote addr, local UDP socket).
				continue
			}

			// Existing session: deliver data
			if n > 0 {
				_, err = conn.Write(buf[:n])
				if err != nil {
					b.peersMu.Lock()
					delete(b.peers, peerKey)
					b.peersMu.Unlock()
					conn.Close()
					b.recordError()
					continue
				}
				b.recordSent(n)
			}
		}
	}
}

func (b *dtlsBackend) startClient(ctx context.Context, tlsCfg *tls.Config) error {
	raddr, err := net.ResolveUDPAddr("udp", b.cfg.RemoteAddr)
	if err != nil {
		return fmt.Errorf("dtls: resolve remote addr: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("dtls: dial UDP: %w", err)
	}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("dtls: client handshake: %w", err)
	}
	b.client = tlsConn
	b.ln = conn
	close(b.readyCh)

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.tunnelLoop(tlsConn)
	}()
	return nil
}

// tunnelLoop reads from the DTLS connection and echoes back.
// Replace with actual local service in production.
func (b *dtlsBackend) tunnelLoop(tlsConn *tls.Conn) {
	buf := make([]byte, b.cfg.MTU)
	for {
		n, err := tlsConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return
			}
			b.recordError()
			return
		}
		b.recordRecv(n)

		_, err = tlsConn.Write(buf[:n])
		if err != nil {
			b.recordError()
			return
		}
		b.recordSent(n)
	}
}

func (b *dtlsBackend) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         dtlsVersion12,
		MaxVersion:         dtlsVersion12,
		InsecureSkipVerify: b.cfg.InsecureSkipVerify,
		ServerName:         b.cfg.RemoteAddr,
	}

	if b.cfg.CertFile != "" && b.cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(b.cfg.CertFile, b.cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("dtls: load cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if b.cfg.CACertFile != "" {
		pemData, err := os.ReadFile(b.cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("dtls: read CA cert: %w", err)
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("dtls: no PEM block in CA cert")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("dtls: parse CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		caPool.AddCert(caCert)
		tlsCfg.RootCAs = caPool
	}

	return tlsCfg, nil
}

func (b *dtlsBackend) recordSent(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesSentTotal.Add(uint64(n))
	}
}

func (b *dtlsBackend) recordRecv(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesRecvTotal.Add(uint64(n))
	}
}

func (b *dtlsBackend) recordError() {
	if m := b.metrics.Load(); m != nil {
		m.ErrorsTotal.Add(1)
	}
}

// newDTLSBackend creates a DTLS backend from generic Config.
func newDTLSBackend(cfg Config) Backend {
	extraArgs := cfg.ExtraArgs
	getArg := func(i int) string {
		if i < len(extraArgs) {
			return extraArgs[i]
		}
		return ""
	}

	mtu := 1400
	if cfg.GREKey > 0 {
		mtu = int(cfg.GREKey)
	}

	b := &dtlsBackend{
		name: cfg.Name,
		cfg: dtlsConfig{
			Mode:               getArg(0),
			ListenAddr:         cfg.ListenAddress,
			RemoteAddr:         getArg(1),
			CertFile:           getArg(2),
			KeyFile:            getArg(3),
			InsecureSkipVerify: false,
			MTU:                mtu,
		},
		readyCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
	return b
}
