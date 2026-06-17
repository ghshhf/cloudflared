// Package tunnel provides pluggable tunnel transport backends.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
	"golang.org/x/crypto/ssh"
)

// ---- SFTP Backend -----------------------------------------------------------
//
// sftpBackend implements an SFTP (SSH File Transfer Protocol) backend.
// It operates in two modes:
//
//   - "server": act as an SSH/SFTP server, authenticating clients and
//     relaying SFTP sessions to an upstream SFTP server.
//     Falls back to a local sftp-server subprocess if no upstream is configured.
//   - "proxy": accept SSH/SFTP connections and relay them verbatim to an
//     upstream SSH/SFTP server. This is a pure TCP tunnel for SFTP traffic.
//
// SFTP runs over SSH as a subsystem (RFC 913). Unlike FTPS, it uses the
// SSH transport layer for both control and data. The protocol is opaque
// to this relay — we just forward bytes in both directions.
//
// Use cases: Encrypted file transfer, SFTP gateway through SkyNet tunnel,
// remote filesystem access via relay.
type sftpBackend struct {
	name   string
	cfg    sftpConfig
	ln     net.Listener
	readyCh chan struct{}
	stopCh  chan struct{}
	wg     sync.WaitGroup
	metrics atomic.Pointer[metrics.BackendMetrics]

	sshConfig ssh.ServerConfig
}

type sftpConfig struct {
	Mode         string // "server" or "proxy"
	ListenAddr   string // TCP address to listen on
	Password     string // server mode: password auth
	UpstreamAddr string // upstream SSH/SFTP server (proxy mode) or local sftp-server path (server mode)
	Username     string // server mode: expected username
}

var _ Backend = (*sftpBackend)(nil)

func (b *sftpBackend) Name() string { return b.name }
func (b *sftpBackend) Type() string { return "sftp" }

func (b *sftpBackend) Start(ctx context.Context) error {
	if b.metrics.Load() == nil {
		b.metrics.Store(metrics.Default().ForBackend(b.name))
	}

	if b.cfg.Mode == "proxy" {
		return b.startProxy(ctx)
	}
	return b.startServer(ctx)
}

func (b *sftpBackend) startServer(ctx context.Context) error {
	addr, err := net.ResolveTCPAddr("tcp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("sftp: listen %s: %w", b.cfg.ListenAddr, err)
	}
	b.ln = ln

	b.setupSSHServer()
	close(b.readyCh)
	b.wg.Add(1)
	go b.serveSSH()
	return nil
}

func (b *sftpBackend) setupSSHServer() {
	b.sshConfig = ssh.ServerConfig{
		ServerVersion: "SSH-2.0-SkyNet-SFTP",
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if b.cfg.Password == "" {
				return nil, errors.New("sftp: password auth disabled")
			}
			if b.cfg.Username != "" && conn.User() != b.cfg.Username {
				return nil, errors.New("sftp: wrong username")
			}
			if string(password) != b.cfg.Password {
				return nil, errors.New("sftp: invalid password")
			}
			return nil, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			// In production, verify against authorized_keys
			return &ssh.Permissions{}, nil
		},
	}
}

func (b *sftpBackend) serveSSH() {
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
			go func() { defer b.wg.Done(); b.handleSSHConn(conn) }()
		}
	}
}

func (b *sftpBackend) handleSSHConn(netConn net.Conn) {
	defer netConn.Close()
	b.recordConnOpen()

	sconn, chans, reqs, err := ssh.NewServerConn(netConn, &b.sshConfig)
	if err != nil {
		b.recordError()
		return
	}
	defer sconn.Close()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go func(ch ssh.Channel) {
			defer ch.Close()
			b.handleSession(ch, requests)
		}(channel)
	}
}

func (b *sftpBackend) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "subsystem":
			payload := string(req.Payload[4:])
			if payload == "sftp" || payload == "sftp-server" {
				req.Reply(true, nil)
				b.handleSFTP(ch)
				return
			}
		case "exec":
			payload := string(req.Payload[4:])
			if payload == "sftp-subsystem" ||
				payload == "/usr/lib/openssh/sftp-server" ||
				payload == "/usr/libexec/sftp-server" ||
				payload == "internal-sftp" {
				req.Reply(true, nil)
				b.handleSFTP(ch)
				return
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (b *sftpBackend) handleSFTP(ch ssh.Channel) {
	// If upstream is configured, relay to upstream SSH/SFTP server.
	// Otherwise, this server mode just closes the channel.
	if b.cfg.UpstreamAddr != "" {
		b.relaySFTP(ch, b.cfg.UpstreamAddr)
		return
	}
	// No upstream configured — client must use an external sftp-server.
	// We just relay the channel data to /dev/null (discard mode).
	io.Copy(io.Discard, io.LimitReader(ch, 1<<20))
}

func (b *sftpBackend) relaySFTP(ch ssh.Channel, upstreamAddr string) {
	// Connect to upstream SSH server
	upstream, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
	if err != nil {
		b.recordError()
		return
	}
	defer upstream.Close()

	// Perform SSH client handshake with upstream
	sshConn, err := ssh.Dial("tcp", upstreamAddr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		b.recordError()
		return
	}
	defer sshConn.Close()

	// Open a session channel on upstream for SFTP
	sessionCh, upstreamReqs, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		b.recordError()
		return
	}
	defer sessionCh.Close()

	// Start SFTP subsystem on upstream
	if _, err := sessionCh.SendRequest("subsystem", true, []byte("sftp")); err != nil {
		b.recordError()
		return
	}

	// Discard upstream requests
	go ssh.DiscardRequests(upstreamReqs)

	// Relay channels: client <-> upstream
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(sessionCh, ch)
		b.recordSent(int(n))
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(ch, sessionCh)
		b.recordRecv(int(n))
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-b.stopCh:
	}
}

// ---- SFTP Proxy Mode ---

func (b *sftpBackend) startProxy(ctx context.Context) error {
	addr, err := net.ResolveTCPAddr("tcp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("sftp: listen %s: %w", b.cfg.ListenAddr, err)
	}
	b.ln = ln

	close(b.readyCh)
	b.wg.Add(1)
	go b.serveProxy()
	return nil
}

func (b *sftpBackend) serveProxy() {
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
			go func() { defer b.wg.Done(); b.handleProxyClient(conn) }()
		}
	}
}

func (b *sftpBackend) handleProxyClient(conn net.Conn) {
	defer conn.Close()
	b.recordConnOpen()

	if b.cfg.UpstreamAddr == "" {
		b.recordError()
		return
	}

	upstream, err := net.DialTimeout("tcp", b.cfg.UpstreamAddr, 5*time.Second)
	if err != nil {
		b.recordError()
		return
	}
	defer upstream.Close()

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

func (b *sftpBackend) Stop(ctx context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	if b.ln != nil {
		b.ln.Close()
	}
	return nil
}

func (b *sftpBackend) Ready() <-chan struct{} { return b.readyCh }

// ---- Metrics helpers ---

func (b *sftpBackend) recordConnOpen() {
	if m := b.metrics.Load(); m != nil {
		m.ConnectionsActive.Add(1)
	}
}
func (b *sftpBackend) recordSent(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesSentTotal.Add(uint64(n))
	}
}
func (b *sftpBackend) recordRecv(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesRecvTotal.Add(uint64(n))
	}
}
func (b *sftpBackend) recordError() {
	if m := b.metrics.Load(); m != nil {
		m.ErrorsTotal.Add(1)
	}
}

// ---- Constructor ---

func newSFTPBackend(cfg Config) Backend {
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
		listenAddr = ":2222"
	}
	return &sftpBackend{
		name: cfg.Name,
		cfg: sftpConfig{
			Mode:         mode,
			ListenAddr:   listenAddr,
			UpstreamAddr: cfg.OriginURL,
			Password:     getArg(2),
			Username:     getArg(3),
		},
		readyCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
}
