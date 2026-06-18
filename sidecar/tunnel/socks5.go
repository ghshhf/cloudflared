package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// socks5Backend implements a minimal RFC1928 SOCKS5 server with CONNECT
// support. Authentication is limited to NO AUTHENTICATION REQUIRED (method
// 0x00). IPv4, IPv6 and domain-name addresses are supported. UDP and BIND
// are NOT implemented — most HTTP/SSH/RDP tunnelling use-cases only need
// CONNECT.
//
// Traffic flow:
//   client <-> [socks5 listener] <-> tcp connection to target
//
// This backend is deliberately dependency-free so it compiles without
// pulling in third-party SOCKS implementations.
type socks5Backend struct {
	cfg Config

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	started  bool
	stopped  bool
}

func newSOCKS5Backend(cfg Config) *socks5Backend {
	return &socks5Backend{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

func (b *socks5Backend) Name() string           { return "socks5://" + b.cfg.Name }
func (b *socks5Backend) Type() string           { return TypeSOCKS5 }
func (b *socks5Backend) Ready() <-chan struct{} { return b.ready }

func (b *socks5Backend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}
	addr := b.cfg.ProxyListen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		b.mu.Unlock()
		return fmt.Errorf("socks5: %w", err)
	}
	b.listener = ln
	b.started = true
	b.mu.Unlock()

	go b.acceptLoop(ctx, ln)

	b.mu.Lock()
	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	b.mu.Unlock()

	return nil
}

func (b *socks5Backend) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if tcpLn, ok := ln.(*net.TCPListener); ok {
			_ = tcpLn.SetDeadline(time.Now().Add(250 * time.Millisecond))
		}

		conn, err := ln.Accept()
		if err != nil {
			b.mu.Lock()
			stopped := b.stopped
			b.mu.Unlock()
			if stopped || ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go b.handleConn(ctx, conn)
	}
}

func (b *socks5Backend) handleConn(ctx context.Context, in net.Conn) {
	defer in.Close()

	// ----------
	// Step 1: Client greeting.
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	// ----------
	header := make([]byte, 2)
	if _, err := io.ReadFull(in, header); err != nil {
		return
	}
	if header[0] != 0x05 { // VER must be 0x05
		return
	}
	nMethods := int(header[1])
	if nMethods <= 0 {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(in, methods); err != nil {
		return
	}

	// Pick method 0x00 (no auth).
	_, _ = in.Write([]byte{0x05, 0x00})

	// ----------
	// Step 2: Client request.
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' | 1    | Variable | 2        |
	// +----+-----+-------+------+----------+----------+
	// ----------
	req := make([]byte, 4)
	if _, err := io.ReadFull(in, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // CONNECT only
		// 0x07 = Command not supported.
		in.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	// req[2] is RSV, ignored.
	atyp := req[3]

	// Read address depending on ATYP.
	var (
		target   string
		addrDone bool
	)
	switch atyp {
	case 0x01: // IPv4: 4 bytes
		ip := make([]byte, 4)
		if _, err := io.ReadFull(in, ip); err != nil {
			return
		}
		target = net.IP(ip).String()
		addrDone = true
	case 0x03: // DOMAINNAME: 1-byte length + domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(in, lenBuf); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(in, domain); err != nil {
			return
		}
		target = string(domain)
		addrDone = true
	case 0x04: // IPv6: 16 bytes
		ip := make([]byte, 16)
		if _, err := io.ReadFull(in, ip); err != nil {
			return
		}
		target = net.IP(ip).String()
		addrDone = true
	default:
		// 0x08 = Address type not supported.
		in.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	if !addrDone {
		return
	}
	// 2-byte port (big-endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(in, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	dst := net.JoinHostPort(target, strconv.Itoa(int(port)))

	// ----------
	// Step 3: Dial target.
	// ----------
	dialer := net.Dialer{Timeout: 10 * time.Second}
	out, err := dialer.DialContext(ctx, "tcp", dst)
	if err != nil {
		// Send generic "connection refused" style reply.
		in.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer out.Close()

	// ----------
	// Step 4: Reply with success.
	// BND.ADDR=0.0.0.0, BND.PORT=0 are the "no specific binding" sentinel
	// values commonly returned by minimal SOCKS servers.
	// ----------
	_, _ = in.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// ----------
	// Step 5: Bidirectional relay.
	// ----------
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(in, out)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(out, in)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (b *socks5Backend) Stop(ctx context.Context) error {
	b.mu.Lock()
	ln := b.listener
	b.listener = nil
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{}) // reset for next Start()
	b.mu.Unlock()

	if ln == nil {
		return nil
	}
	return ln.Close()
}

// ListenAddr returns the effective bound address after Start succeeds.
func (b *socks5Backend) ListenAddr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listener == nil {
		return ""
	}
	addr := b.listener.Addr().String()
	// strip tcp/ prefix if any returned by the net package
	return strings.TrimPrefix(addr, "tcp://")
}
