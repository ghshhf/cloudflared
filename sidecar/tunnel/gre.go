// Package tunnel provides pluggable tunnel transport backends.
// See backend.go for the Backend interface and the NewBackend registry.
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
	"github.com/cloudflare/cloudflared/sidecar/packet"
)

// ---- Packet Tunnel Backend (IP over TCP/UDP with GRE encapsulation) -----

// packetTunnelBackend implements "packet tunnel" mode: it accepts raw IP
// packets from a TUN interface or raw socket, encapsulates them in GRE
// (or direct IP-over-TCP), and forwards to a remote peer over TCP.
//
// This gives us L3 (IP) level tunneling — one device gets a virtual IP
// from the remote network and can route full IP traffic through the tunnel.
// Much more capable than port forwarding; supports VPN-style use cases.
type packetTunnelBackend struct {
	cfg Config

	mu      sync.Mutex
	listener net.Listener
	ready    chan struct{}
	started  bool
	stopped  bool

	// Local TUN settings
	tunIP   net.IP // virtual IP assigned to us
	gwIP    net.IP // default gateway on remote side
	greKey  uint32 // GRE key for demultiplexing

	// Statistics
	stats packet.PacketStats
}

// newPacketTunnelBackend creates a GRE-over-TCP packet tunnel backend.
func newPacketTunnelBackend(cfg Config) *packetTunnelBackend {
	return &packetTunnelBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
		greKey: 0xC0FFEE42, // default GRE key
	}
}

func (b *packetTunnelBackend) Name() string { return "packet-tunnel://" + b.cfg.Name }
func (b *packetTunnelBackend) Type() string { return "packet-tunnel" }
func (b *packetTunnelBackend) Ready() <-chan struct{} { return b.ready }

func (b *packetTunnelBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	// Parse GRE key from config if provided.
	if b.cfg.GREKey != 0 {
		b.greKey = b.cfg.GREKey
	}

	// For the server side: listen on a TCP port and accept GRE-wrapped packets.
	// For the client side: connect to the remote peer.
	// Here we implement the server/listener mode for simplicity.
	// A future client-side mode would dial the remote and pipe GRE traffic.

	listenAddr := b.cfg.ListenAddress
	if listenAddr == "" {
		listenAddr = "0.0.0.0:0" // OS picks a free port
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		b.mu.Unlock()
		metrics.SetAvailable("packet-tunnel", false)
		return err
	}

	b.listener = ln
	b.started = true
	b.mu.Unlock()

	metrics.SetAvailable("packet-tunnel", true)

	// Accept connections and handle GRE-wrapped IP packets.
	go b.acceptLoop(ctx, ln)

	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	return nil
}

func (b *packetTunnelBackend) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tcpLn, ok := ln.(*net.TCPListener)
		if ok {
			_ = tcpLn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}

		conn, err := ln.Accept()
		if err != nil {
			if b.stopped || ctx.Err() != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			b.handleGREStream(c)
		}(conn)
	}
}

// handleGREStream reads GRE-wrapped IP packets from a TCP stream.
// Each packet is prefixed with a 4-byte length field (network byte order).
func (b *packetTunnelBackend) handleGREStream(conn net.Conn) {
	buf := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read 4-byte length prefix.
		var lengthBuf [4]byte
		_, err := io.ReadFull(conn, lengthBuf[:])
		if err != nil {
			b.stats.Dropped++
			metrics.RecordError("packet-tunnel")
			return
		}
		length := binary.BigEndian.Uint32(lengthBuf[:])
		if length > 65507 { // max IP packet size
			b.stats.Dropped++
			b.stats.WrongProto++
			return
		}

		// Read the GRE-wrapped packet.
		n, err := io.ReadFull(conn, buf[:length])
		if err != nil {
			b.stats.Dropped++
			metrics.RecordError("packet-tunnel")
			return
		}

		b.stats.Received++
		metrics.RecordTransfer("packet-tunnel", 0, int64(n))

		// Parse GRE header.
		greHdr, payload, err := packet.ParseGRE(buf[:n])
		if err != nil {
			b.stats.WrongProto++
			b.stats.Dropped++
			continue
		}

		// Check GRE key.
		if greHdr.Key != 0 && greHdr.Key != b.greKey {
			b.stats.Dropped++
			continue
		}

		// Parse inner IP header.
		_, _, err = packet.ParseIPv4Header(payload)
		if err != nil {
			b.stats.WrongProto++
			b.stats.Dropped++
			continue
		}

		// Deliver to local network stack.
		// For a real TUN integration this would write to a TUN device.
		// Here we forward to the origin URL as a demonstration.
		b.forwardToOrigin(buf[:n])
	}
}

// forwardToOrigin sends the tunnel packet to the configured origin.
func (b *packetTunnelBackend) forwardToOrigin(data []byte) {
	if b.cfg.OriginURL == "" {
		return
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", b.cfg.OriginURL)
	if err != nil {
		metrics.RecordError("packet-tunnel")
		return
	}
	defer conn.Close()
	conn.Write(data)
}

func (b *packetTunnelBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	ln := b.listener
	b.listener = nil
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{})
	b.mu.Unlock()

	metrics.SetAvailable("packet-tunnel", false)
	if ln == nil {
		return nil
	}
	return ln.Close()
}

// ---- GRE Backend --------------------------------------------------------

// greBackend implements a GRE tunnel endpoint. It wraps raw IP packets
// inside GRE and forwards them over a TCP connection to a remote GRE peer.
// Unlike packet-tunnel, GRE mode uses the standard GRE protocol directly.
type greBackend struct {
	cfg Config

	mu      sync.Mutex
	conn    net.Conn
	ready   chan struct{}
	started bool
	stopped bool

	greKey uint32
}

// newGREBackend creates a GRE-over-TCP backend.
func newGREBackend(cfg Config) *greBackend {
	return &greBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
		greKey: 0xC0FFEE42,
	}
}

func (b *greBackend) Name() string { return "gre://" + b.cfg.Name }
func (b *greBackend) Type() string { return "gre" }
func (b *greBackend) Ready() <-chan struct{} { return b.ready }

func (b *greBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	if b.cfg.RelayTarget == "" {
		b.mu.Unlock()
		return errors.New("gre: empty relay_target; set relay_target for GRE peer")
	}

	if b.cfg.GREKey != 0 {
		b.greKey = b.cfg.GREKey
	}

	// Connect to GRE peer (TCP socket acting as GRE transport).
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", b.cfg.RelayTarget)
	if err != nil {
		b.mu.Unlock()
		metrics.SetAvailable("gre", false)
		return fmt.Errorf("gre: dial peer %s: %w", b.cfg.RelayTarget, err)
	}

	b.conn = conn
	b.started = true
	b.mu.Unlock()

	metrics.SetAvailable("gre", true)
	close(b.ready)
	return nil
}

func (b *greBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{})
	metrics.SetAvailable("gre", false)
	return nil
}

// EncapsulateGRE takes an IP packet and wraps it in GRE + outer IP.
func (b *greBackend) Encapsulate(pkt []byte) ([]byte, error) {
	localIP := net.ParseIP("10.8.0.2") // placeholder — configured via config
	peerIP := net.ParseIP("10.8.0.1")
	return packet.EncapsulateIPOverGRE(pkt, localIP, peerIP, b.greKey)
}

// ---- UDP Tunnel Backend --------------------------------------------------

// udpTunnelBackend implements a UDP tunnel: wraps IP packets in UDP.
// Used for VXLAN and for simple high-performance L3 tunneling.
type udpTunnelBackend struct {
	cfg Config

	mu      sync.Mutex
	conn    *net.UDPConn
	ready   chan struct{}
	started bool
	stopped bool

	recvBytes int64
}

// newUDPTunnelBackend creates a UDP tunnel backend.
func newUDPTunnelBackend(cfg Config) *udpTunnelBackend {
	return &udpTunnelBackend{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

func (b *udpTunnelBackend) Name() string { return "udp-tunnel://" + b.cfg.Name }
func (b *udpTunnelBackend) Type() string { return "udp-tunnel" }
func (b *udpTunnelBackend) Ready() <-chan struct{} { return b.ready }

func (b *udpTunnelBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	listenAddr := b.cfg.ListenAddress
	if listenAddr == "" {
		listenAddr = "0.0.0.0:0"
	}

	lnAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		b.mu.Unlock()
		return err
	}

	conn, err := net.ListenUDP("udp", lnAddr)
	if err != nil {
		b.mu.Unlock()
		metrics.SetAvailable("udp-tunnel", false)
		return err
	}

	b.conn = conn
	b.started = true
	b.mu.Unlock()

	metrics.SetAvailable("udp-tunnel", true)
	go b.recvLoop(ctx, conn)

	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	return nil
}

func (b *udpTunnelBackend) recvLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if b.stopped || ctx.Err() != nil {
				return
			}
			continue
		}

		_ = addr // peer address for logging / ACL

		// Parse and forward to origin.
		b.IncRecv(int64(n))
		if b.cfg.OriginURL != "" {
			go b.forwardToOrigin(buf[:n])
		}
	}
}

func (b *udpTunnelBackend) forwardToOrigin(data []byte) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", b.cfg.OriginURL)
	if err != nil {
		metrics.RecordError("udp-tunnel")
		return
	}
	defer conn.Close()
	conn.Write(data)
}

func (b *udpTunnelBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{})
	metrics.SetAvailable("udp-tunnel", false)
	return nil
}

// ---- tiny stats helper --------------------------------------------------

func (b *udpTunnelBackend) IncRecv(n int64) { atomic.AddInt64(&b.recvBytes, n) }
