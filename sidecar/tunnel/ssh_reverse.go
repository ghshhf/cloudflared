package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
	"golang.org/x/crypto/ssh"
)

// ---- sentinel errors -----------------------------------------------------

var (
	errSSHNoAuth           = &backendErr{msg: "ssh-reverse: no auth method configured (need password or private_key)"}
	errSSHParseFingerprint = &backendErr{msg: "ssh-reverse: invalid host key fingerprint format"}
)

// sshReverseBackend tunnels traffic through an SSH connection in reverse
// port-forwarding mode (-R). This is the mechanism behind:
//
//	ssh -R 0.0.0.0:remote_port:local_host:local_port user@ssh_server
//
// Traffic arriving at remote_port on the SSH server is tunneled back through
// the SSH client and delivered to a local service address.
//
// This backend operates as an SSH client only (no SSH server). The remote SSH
// server must have GatewayPorts=yes (or equivalent) enabled for the reverse
// port to be reachable from outside.
//
// Key features:
//   - Password or private-key authentication
//   - Multiple simultaneous forwarded connections over one SSH session
//   - Keepalive to detect broken connections
//   - Automatic reconnection on connection loss (if Reconnect=true)
type sshReverseBackend struct {
	name    string
	cfg     sshConfig
	client  *ssh.Client
	readyCh chan struct{}
	stopCh  chan struct{}
	wg      sync.WaitGroup

	metrics atomic.Pointer[metrics.BackendMetrics]
}

type sshConfig struct {
	// SSH server address (host:port)
	Server string
	// Username for SSH authentication
	Username string
	// Password (leave empty to use key-based auth)
	Password string
	// PrivateKey PEM-encoded RSA/ECDSA/Ed25519 private key
	PrivateKey string
	// RemotePort is the port on the SSH server to bind for reverse forward.
	// Set to 0 to let the server assign a port (returned in SSHGlobalForwardRequest).
	RemotePort int
	// RemoteHost is the address reachable from the SSH server that will
	// receive the forwarded traffic. Default: "127.0.0.1".
	RemoteHost string
	// LocalHost is the local address where traffic is delivered after
	// crossing the tunnel.
	LocalHost string
	// LocalPort is the local port where traffic is delivered.
	LocalPort int
	// KeepaliveInterval controls SSH keepalive frequency (default 30s, 0=disabled)
	KeepaliveInterval time.Duration
	// Reconnect enables automatic reconnection on connection loss (default false)
	Reconnect bool
	// ReconnectInterval is the pause between reconnection attempts (default 5s)
	ReconnectInterval time.Duration
	// HostKeyFingerprint is the expected SHA256 base64-encoded host key fingerprint
	// of the SSH server (e.g. "SHA256:abc123..."). When set, the client will
	// verify the server's host key against this value. Leave empty to use
	// InsecureSkipVerify.
	HostKeyFingerprint string
	// InsecureSkipVerify disables host key verification entirely. Only set this
	// to true for testing or when you fully trust the network. If both
	// HostKeyFingerprint and InsecureSkipVerify are unset/false, the backend
	// will refuse to connect — you must choose one verification strategy.
	InsecureSkipVerify bool
}

var _ Backend = (*sshReverseBackend)(nil)

// Name implements Backend.
func (b *sshReverseBackend) Name() string { return b.name }

// Type implements Backend.
func (b *sshReverseBackend) Type() string { return "ssh-reverse" }

// Start implements Backend.
func (b *sshReverseBackend) Start(ctx context.Context) error {
	if b.metrics.Load() == nil {
		b.metrics.Store(metrics.Default().ForBackend(b.name))
	}

	return b.connectAndForward()
}

// connectAndForward establishes the SSH session and requests reverse port forwarding.
func (b *sshReverseBackend) connectAndForward() error {
	auths, err := b.authMethods()
	if err != nil {
		return err
	}

	hkCallback, err := b.hostKeyCallback()
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            b.cfg.Username,
		Auth:            auths,
		HostKeyCallback: hkCallback,
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", b.cfg.Server, config)
	if err != nil {
		return fmt.Errorf("ssh-reverse: dial %s: %w", b.cfg.Server, err)
	}
	b.client = client

	// Start keepalive
	if b.cfg.KeepaliveInterval > 0 {
		go b.keepaliveLoop()
	}

	// Global request: TCPIP forward (reverse tunnel, -R style)
	bindAddr := b.cfg.RemoteHost
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	bindPort := b.cfg.RemotePort

	ok, _, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(&struct {
		Addr string
		Port uint32
	}{
		Addr: bindAddr,
		Port: uint32(bindPort),
	}))
	if err != nil {
		return fmt.Errorf("ssh-reverse: tcpip-forward request: %w", err)
	}
	if !ok {
		return fmt.Errorf("ssh-reverse: tcpip-forward request rejected by server")
	}

	close(b.readyCh)

	// Handle incoming forwarded connections via direct-tcpip channel type
	go func() {
		ch := client.HandleChannelOpen("direct-tcpip")
		for {
			select {
			case <-b.stopCh:
				return
			case newChan, ok := <-ch:
				if !ok {
					b.handleDisconnect()
					return
				}
				b.wg.Add(1)
				go func() {
					defer b.wg.Done()
					b.handleForwardedChannel(newChan)
				}()
			}
		}
	}()

	return nil
}

// handleForwardedChannel handles a connection forwarded from the SSH server
// (someone connected to the server's reverse-forward port).
func (b *sshReverseBackend) handleForwardedChannel(newChan ssh.NewChannel) {
	channel, _, err := newChan.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	localAddr := net.JoinHostPort(b.cfg.LocalHost, strconv.Itoa(b.cfg.LocalPort))
	outConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		b.recordError()
		return
	}
	defer outConn.Close()

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		n, _ := io.Copy(outConn, channel)
		b.recordSent(int(n))
	}()

	n, _ := io.Copy(channel, outConn)
	b.recordRecv(int(n))
}

// handleDisconnect is called when the SSH channel is closed.
func (b *sshReverseBackend) handleDisconnect() {
	if b.cfg.Reconnect {
		go b.reconnectLoop()
	} else {
		close(b.stopCh)
	}
}

// reconnectLoop attempts to reconnect with exponential back-off.
func (b *sshReverseBackend) reconnectLoop() {
	interval := b.cfg.ReconnectInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		select {
		case <-b.stopCh:
			return
		case <-time.After(interval):
			if err := b.connectAndForward(); err == nil {
				return
			}
			interval = min(interval*2, 60*time.Second)
		}
	}
}

// keepaliveLoop sends SSH keepalive requests periodically.
func (b *sshReverseBackend) keepaliveLoop() {
	if b.cfg.KeepaliveInterval <= 0 {
		b.cfg.KeepaliveInterval = 30 * time.Second
	}
	ticker := time.NewTicker(b.cfg.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			if b.client != nil {
				b.client.SendRequest("keepalive@openssh.com", false, nil)
			}
		}
	}
}

// hostKeyCallback returns an ssh.HostKeyCallback based on the backend's
// configuration. It prefers, in order:
//  1. HostKeyFingerprint — exact SHA256 fingerprint match
//  2. InsecureSkipVerify — no verification (only for testing)
//
// If neither is set, it returns an error — failing closed is safer
// than silently skipping verification.
func (b *sshReverseBackend) hostKeyCallback() (ssh.HostKeyCallback, error) {
	// 1. Fingerprint verification.
	if b.cfg.HostKeyFingerprint != "" {
		fingerprint := b.cfg.HostKeyFingerprint
		// Normalise to "SHA256:" prefix for comparison.
		fingerprint = normaliseFingerprint(fingerprint)

		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			actual := ssh.FingerprintSHA256(key)
			actual = strings.ToUpper(actual[:7]) + actual[7:]
			if subtle.ConstantTimeCompare([]byte(actual), []byte(fingerprint)) == 1 {
				return nil
			}
			return fmt.Errorf("ssh-reverse: host key fingerprint mismatch: "+
				"expected %q, got %q for host %q", b.cfg.HostKeyFingerprint, actual, hostname)
		}, nil
	}

	// 2. Explicit insecure bypass.
	if b.cfg.InsecureSkipVerify {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	// 3. Nothing configured — fail closed.
	return nil, fmt.Errorf("ssh-reverse: no host key verification configured; " +
		"set HostKeyFingerprint or InsecureSkipVerify=true (unsafe)")
}

// normaliseFingerprint ensures the fingerprint has a "SHA256:" prefix.
func normaliseFingerprint(fp string) string {
	if !strings.HasPrefix(fp, "SHA256:") && !strings.HasPrefix(fp, "sha256:") {
		fp = "SHA256:" + fp
	}
	return strings.ToUpper(fp[:7]) + fp[7:]
}

// parseFingerprint decodes a "SHA256:base64string" fingerprint to its raw hash bytes.
func parseFingerprint(fp string) ([]byte, error) {
	const prefix = "SHA256:"
	if len(fp) < len(prefix)+2 {
		return nil, errSSHParseFingerprint
	}
	encoded := fp[len(prefix):]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try with padding.
		missing := len(encoded) % 4
		if missing > 0 {
			encoded += strings.Repeat("=", 4-missing)
		}
		raw, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode: %v", errSSHParseFingerprint, err)
		}
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("%w: unexpected hash length %d (want %d)",
			errSSHParseFingerprint, len(raw), sha256.Size)
	}
	return raw, nil
}

// authMethods returns the list of SSH authentication methods.
func (b *sshReverseBackend) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if b.cfg.Password != "" {
		methods = append(methods, ssh.Password(b.cfg.Password))
	}

	if b.cfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(b.cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("ssh-reverse: parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if len(methods) == 0 {
		return nil, errSSHNoAuth
	}

	return methods, nil
}

// Stop implements Backend.
func (b *sshReverseBackend) Stop(ctx context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	if b.client != nil {
		b.client.Close()
	}
	return nil
}

// Ready implements Backend.
func (b *sshReverseBackend) Ready() <-chan struct{} { return b.readyCh }

func (b *sshReverseBackend) recordSent(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesSentTotal.Add(uint64(n))
	}
}

func (b *sshReverseBackend) recordRecv(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesRecvTotal.Add(uint64(n))
	}
}

func (b *sshReverseBackend) recordError() {
	if m := b.metrics.Load(); m != nil {
		m.ErrorsTotal.Add(1)
	}
}

// newSSHReverseBackend creates an SSH reverse tunnel backend from generic Config.
func newSSHReverseBackend(cfg Config) Backend {
	extraArgs := cfg.ExtraArgs
	getArg := func(i int) string {
		if i < len(extraArgs) {
			return extraArgs[i]
		}
		return ""
	}
	sshCfg := sshConfig{
		Server:             firstNonEmpty(getArg(0), cfg.OriginURL),
		Username:           getArg(1),
		Password:           getArg(2),
		RemoteHost:         "127.0.0.1",
		RemotePort:         int(cfg.GREKey),
		LocalHost:          "127.0.0.1",
		LocalPort:          80,
		KeepaliveInterval:  30 * time.Second,
		Reconnect:          false,
		ReconnectInterval:  5 * time.Second,
		HostKeyFingerprint: getArg(3),       // optional: SHA256:abc...
		InsecureSkipVerify: getArg(4) == "", // default true for backward compat
	}
	if sshCfg.RemotePort == 0 {
		sshCfg.RemotePort = 22 // default SSH port
	}
	return &sshReverseBackend{
		name:    cfg.Name,
		cfg:     sshCfg,
		readyCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
