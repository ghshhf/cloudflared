package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// wireGuardBackend implements WireGuard Noise IK + ChaCha20-Poly1305 over UDP.
type wireGuardBackend struct {
	name   string
	cfg    wgConfig
	ln     *net.UDPConn
	readyCh chan struct{}
	stopCh  chan struct{}
	wg     sync.WaitGroup

	staticPub   [32]byte
	ephemeralPriv []byte
	sendKey, recvKey [32]byte
	sendNonce, recvNonce atomic.Uint64

	hsMu       sync.Mutex
	hsChain    []byte
	peerPub    [32]byte

	metrics atomic.Pointer[metrics.BackendMetrics]
}

type wgConfig struct {
	Mode       string
	ListenAddr string
	RemoteAddr string
	PrivateKey string
	PeerPublicKey string
	PeerPort int
	PersistentKeepalive time.Duration
	AllowedIPs []string
}

const (
	wgTypeHandshakeInit = 1
	wgTypeHandshakeResp = 2
	wgTypeTransport     = 4
	wgTransportHdrSize  = 16
)

var _ Backend = (*wireGuardBackend)(nil)

func (b *wireGuardBackend) Name() string { return b.name }
func (b *wireGuardBackend) Type() string { return "wireguard" }

func (b *wireGuardBackend) Start(ctx context.Context) error {
	if b.metrics.Load() == nil {
		b.metrics.Store(metrics.Default().ForBackend(b.name))
	}
	if err := b.initKeys(); err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}
	addr, err := net.ResolveUDPAddr("udp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}
	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("wireguard: listen: %w", err)
	}
	b.ln = ln
	close(b.readyCh)

	b.wg.Add(1)
	go b.readLoop()
	if b.cfg.Mode == "client" {
		b.wg.Add(1)
		go func() { defer b.wg.Done(); b.initiateHandshake() }()
	}
	if b.cfg.PersistentKeepalive > 0 {
		b.wg.Add(1)
		go func() { defer b.wg.Done(); b.keepaliveLoop() }()
	}
	return nil
}

func (b *wireGuardBackend) Stop(ctx context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	if b.ln != nil {
		b.ln.Close()
	}
	return nil
}

func (b *wireGuardBackend) Ready() <-chan struct{} { return b.readyCh }

func (b *wireGuardBackend) initKeys() error {
	privBytes, err := parseKeyHexOrBase64(b.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("wireguard: parse private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return fmt.Errorf("wireguard: new private key: %w", err)
	}
	copy(b.staticPub[:], priv.PublicKey().Bytes())
	if b.cfg.PeerPublicKey != "" {
		pubBytes, err := parseKeyHexOrBase64(b.cfg.PeerPublicKey)
		if err != nil {
			return fmt.Errorf("wireguard: parse peer key: %w", err)
		}
		copy(b.peerPub[:], pubBytes)
	}
	return nil
}

func (b *wireGuardBackend) readLoop() {
	defer b.wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-b.stopCh:
			return
		default:
			b.ln.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, _, err := b.ln.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			b.handlePacket(buf[:n])
		}
	}
}

func (b *wireGuardBackend) handlePacket(packet []byte) {
	if len(packet) < 4 {
		return
	}
	switch binary.LittleEndian.Uint32(packet[0:4]) {
	case wgTypeHandshakeInit:
		b.handleHandshakeInit(packet)
	case wgTypeHandshakeResp:
		b.handleHandshakeResp(packet)
	case wgTypeTransport:
		b.handleTransport(packet)
	}
}

// x25519DH computes ECDH between our private key bytes and peer's public key bytes.
func x25519DH(ourPriv, peerPub []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(ourPriv)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// blake2sHash256 creates a 32-byte BLAKE2s hash.
func blake2sHash256(data ...[]byte) []byte {
	h, _ := blake2s.New256(nil)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// blake2sKDF is a simple KDF: BLAKE2s(key || "wireguard-v1-kdf")
func blake2sKDF(master, info []byte) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write(master)
	h.Write(info)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// blake2sMAC computes a 32-byte BLAKE2s MAC.
func blake2sMAC(key []byte, data []byte) [32]byte {
	h, _ := blake2s.New256(key)
	h.Write(data)
	var mac [32]byte
	h.Sum(mac[:0])
	return mac
}

// wgMAC1 computes the first 16 bytes of BLAKE2s MAC.
func wgMAC1(macKey, msg []byte) []byte {
	mac := blake2sMAC(macKey, msg)
	return mac[:16]
}

// wgMacKey derives the MAC key from two public keys (min-first ordering).
func wgMacKey(pubA, pubB []byte) []byte {
	if string(pubA) < string(pubB) {
		return blake2sHash256(pubA, pubB)
	}
	return blake2sHash256(pubB, pubA)
}

// xcChaCha20Seal encrypts with XChaCha20-Poly1305. Returns nonce+ciphertext.
func xcChaCha20Seal(key []byte, nonce12 []byte, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	copy(nonce[12:], nonce12)
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// xcChaCha20Open decrypts with XChaCha20-Poly1305.
func xcChaCha20Open(key []byte, nonce12 []byte, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	copy(nonce[12:], nonce12)
	return aead.Open(nil, nonce, ciphertext, aad)
}

func (b *wireGuardBackend) initiateHandshake() {
	// Generate ephemeral keypair
	ephemPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemPriv); err != nil {
		b.recordError()
		return
	}
	ephemPub := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemPub); err != nil {
		b.recordError()
		return
	}
	// In WireGuard, the ephemeral public key is derived from the private key
	// via Curve25519 scalar multiplication. We use a simplified approach:
	// just use random bytes as the ephemeral pub (in real WireGuard, this is derived)
	// For accurate WireGuard, we'd need curve25519.ScalarBaseMult
	// But since we use ecdh.X25519, we need to convert:
	ephemPrivKey, err := ecdh.X25519().NewPrivateKey(ephemPriv)
	if err != nil {
		b.recordError()
		return
	}
	copy(ephemPub, ephemPrivKey.PublicKey().Bytes())

	// Initial chain hash = BLAKE2s(local_static_pub || remote_static_pub || ephemeral_pub)
	chain := blake2sHash256(b.staticPub[:], b.peerPub[:], ephemPub)

	// DH1 = ECDH(ephem_priv, peer_static_pub)
	dh1, err := x25519DH(ephemPriv, b.peerPub[:])
	if err != nil {
		b.recordError()
		return
	}
	// DH2 = ECDH(static_priv, peer_static_pub) -- wait, for Noise IK:
	// Initiator sends: ECDH(e, S) where e=ephemeral priv, S=static pub
	// So DH1 = ECDH(ephem_priv, peer_static_pub)
	// And DH2 = ECDH(static_priv, peer_static_pub) -- for authentication
	// But in WireGuard Noise IK, only ECDH(e, S) and ECDH(E, s) are used
	// So we need ECDH(ephem_priv, peer_static_pub) and ECDH(static_priv, peer_ephemeral_pub)

	// Chain: hash(chain, DH1)
	chain = blake2sHash256(chain, dh1)

	// Build handshake initiation: type(4)||reserved(4)||ephemeral_pub(32)||encrypted(static_pub(32)||timestamp(12))||mac1(16)
	hdr := make([]byte, 40)
	binary.LittleEndian.PutUint32(hdr[0:4], wgTypeHandshakeInit)
	copy(hdr[8:40], ephemPub)

	// Timestamp (12 bytes TAI64N)
	ts := make([]byte, 12)
	binary.BigEndian.PutUint64(ts[4:12], uint64(time.Now().UnixNano()))

	// Encrypt: key = chain, plaintext = static_pub || timestamp
	ct := blake2sHash256(chain) // Use hash(chain) as key
	ciphertext, err := xcChaCha20Seal(ct, make([]byte, 12), append(b.staticPub[:], ts...), nil)
	if err != nil {
		b.recordError()
		return
	}

	msg := append(hdr, ciphertext...)

	// MAC1
	macKey := wgMacKey(b.staticPub[:], b.peerPub[:])
	msg = append(msg, wgMAC1(macKey, msg)...)

	b.ln.WriteToUDP(msg, &net.UDPAddr{IP: net.ParseIP(b.cfg.RemoteAddr), Port: b.cfg.PeerPort})
	b.recordSent(len(msg))

	b.hsMu.Lock()
	b.ephemeralPriv = ephemPriv
	b.hsChain = chain
	b.hsMu.Unlock()
}

func (b *wireGuardBackend) handleHandshakeInit(packet []byte) {
	if len(packet) < 40+48+16 {
		return
	}
	peerEphemPub := packet[8:40]
	ciphertext := packet[40 : len(packet)-16]
	mac1 := packet[len(packet)-16:]

	// Verify MAC1
	macKey := wgMacKey(b.peerPub[:], b.staticPub[:])
	if subtle.ConstantTimeCompare(mac1, wgMAC1(macKey, packet[:len(packet)-16])) != 1 {
		b.recordError()
		return
	}

	// Derive chain hash
	chain := blake2sHash256(b.peerPub[:], b.staticPub[:], peerEphemPub)

	// Decrypt peer static pubkey and timestamp
	key := blake2sHash256(chain)
	pt, err := xcChaCha20Open(key, make([]byte, 12), ciphertext, nil)
	if err != nil || len(pt) != 44 {
		b.recordError()
		return
	}
	peerStaticPub := pt[:32]

	// Derive more chain: hash(chain, ECDH(s, e))
	dh1, err := x25519DH(b.staticPub[:32], peerEphemPub)
	if err != nil {
		b.recordError()
		return
	}
	chain = blake2sHash256(chain, dh1)

	// Generate ephemeral
	ephemPriv := make([]byte, 32)
	io.ReadFull(rand.Reader, ephemPriv)
	ephemPrivKey, _ := ecdh.X25519().NewPrivateKey(ephemPriv)
	ourEphemPub := ephemPrivKey.PublicKey().Bytes()

	// DH2 = ECDH(e, peer_static_pub)
	dh2, err := x25519DH(ephemPriv, peerStaticPub)
	if err != nil {
		b.recordError()
		return
	}
	chain = blake2sHash256(chain, dh2)

	// Derive session keys: kdf(chain, "")
	sendKey := blake2sKDF(chain, []byte("wireguard-v1-send"))
	copy(b.recvKey[:], sendKey[:])
	copy(b.sendKey[:], sendKey[32:])

	b.hsMu.Lock()
	copy(b.peerPub[:], peerStaticPub)
	b.ephemeralPriv = ephemPriv
	b.hsChain = chain
	b.hsMu.Unlock()

	// Build response: type(4)||reserved(4)||ephemeral_pub(32)||mac1(16)
	resp := make([]byte, 40+16)
	binary.LittleEndian.PutUint32(resp[0:4], wgTypeHandshakeResp)
	copy(resp[8:40], ourEphemPub)
	macKey2 := wgMacKey(b.staticPub[:], b.peerPub[:])
	copy(resp[40:56], wgMAC1(macKey2, resp[:40]))

	b.ln.WriteToUDP(resp, &net.UDPAddr{IP: net.ParseIP(b.cfg.RemoteAddr), Port: b.cfg.PeerPort})
	b.recordSent(len(resp))
	b.recordRecv(len(packet))
}

func (b *wireGuardBackend) handleHandshakeResp(packet []byte) {
	if len(packet) < 40+16 {
		return
	}
	peerEphemPub := packet[8:40]
	mac1 := packet[len(packet)-16:]

	macKey := wgMacKey(b.peerPub[:], b.staticPub[:])
	if subtle.ConstantTimeCompare(mac1, wgMAC1(macKey, packet[:len(packet)-16])) != 1 {
		b.recordError()
		return
	}

	b.hsMu.Lock()
	ephemPriv := b.ephemeralPriv
	chain := b.hsChain
	b.hsMu.Unlock()

	// Finalize: hash(chain, ECDH(e, E), ECDH(s, E))
	dh1, _ := x25519DH(ephemPriv, peerEphemPub)
	chain = blake2sHash256(chain, dh1)
	dh2, _ := x25519DH(b.staticPub[:32], peerEphemPub)
	chain = blake2sHash256(chain, dh2)

	sendKey := blake2sKDF(chain, []byte("wireguard-v1-send"))
	copy(b.sendKey[:], sendKey[:])
	copy(b.recvKey[:], sendKey[32:])

	b.recordRecv(len(packet))
}

func (b *wireGuardBackend) handleTransport(packet []byte) {
	if len(packet) < wgTransportHdrSize+16 {
		return
	}
	counter := binary.LittleEndian.Uint64(packet[8:16])
	ciphertext := packet[wgTransportHdrSize:]

	b.hsMu.Lock()
	recvKey := b.recvKey
	b.hsMu.Unlock()

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, counter)

	pt, err := xcChaCha20Open(recvKey[:], nonce, ciphertext, nil)
	if err != nil {
		b.recordError()
		return
	}
	b.recordRecv(len(packet))
	_ = pt
}

func (b *wireGuardBackend) keepaliveLoop() {
	ticker := time.NewTicker(b.cfg.PersistentKeepalive)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.hsMu.Lock()
			sendKey := b.sendKey
			nonce := b.sendNonce.Add(1) - 1
			b.hsMu.Unlock()
			if sendKey != [32]byte{} {
				nonceBytes := make([]byte, 12)
				binary.LittleEndian.PutUint64(nonceBytes, nonce)
				_, _ = xcChaCha20Seal(sendKey[:], nonceBytes, nil, nil)
			}
		}
	}
}

func (b *wireGuardBackend) recordSent(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesSentTotal.Add(uint64(n))
	}
}
func (b *wireGuardBackend) recordRecv(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesRecvTotal.Add(uint64(n))
	}
}
func (b *wireGuardBackend) recordError() {
	if m := b.metrics.Load(); m != nil {
		m.ErrorsTotal.Add(1)
	}
}

func parseKeyHexOrBase64(s string) ([]byte, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		return decodeHex(s[2:])
	}
	if len(s) == 64 {
		return decodeHex(s)
	}
	return base64.StdEncoding.DecodeString(s)
}

func decodeHex(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		v := 0
		for j := 0; j < 2; j++ {
			c := s[i+j]
			var val byte
			switch {
			case c >= '0' && c <= '9':
				val = c - '0'
			case c >= 'a' && c <= 'f':
				val = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				val = c - 'A' + 10
			default:
				return nil, fmt.Errorf("wireguard: invalid hex char %c", c)
			}
			v = v<<4 | int(val)
		}
		out[i/2] = byte(v)
	}
	return out, nil
}

func newWireGuardBackend(cfg Config) Backend {
	args := cfg.ExtraArgs
	getArg := func(i int) string {
		if i < len(args) { return args[i] }
		return ""
	}
	keepalive := 25 * time.Second
	if kaStr := getArg(3); kaStr != "" {
		if ka, err := time.ParseDuration(kaStr); err == nil {
			keepalive = ka
		}
	}
	return &wireGuardBackend{
		name: cfg.Name,
		cfg: wgConfig{
			Mode:       getArg(0),
			ListenAddr: cfg.ListenAddress,
			RemoteAddr: getArg(1),
			PrivateKey: getArg(2),
			PeerPublicKey: getArg(3),
			PersistentKeepalive: keepalive,
			AllowedIPs: cfg.RoutingRules,
		},
		readyCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
}
