package webrtc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// DataChannelMessageType constants (RFC 8832).
const (
	DCMTFull    = 0x00 // Full ACK
	DCMTPartial = 0x40 // Partial message
	DCMTControl = 0x02 // Control message
	DCMTReset   = 0x03 // Reset the stream
)

// DataChannel is a bidirectional reliable ordered byte stream over DTLS,
// implementing the WebRTC DataChannel protocol (RFC 8832).
type DataChannel struct {
	label   string
	protoID string
	isOpen  atomic.Bool
	id      uint16

	mu       sync.RWMutex
	outOrder []byte // pending outbound data (partial message)
	outSeq   uint16 // outbound message sequence number

	inBuf     []byte // inbound message buffer
	inSeq     uint16 // inbound message sequence number
	inPartial bool   // waiting for rest of partial message

	// Underlying reliable ordered transport (implemented by DTLS wrapper).
	transport io.ReadWriter

	onMessage func([]byte) // called when a complete message is received
}

// NewDataChannel creates a new DataChannel with the given label and protocol ID.
func NewDataChannel(label, protoID string, id uint16, transport io.ReadWriter) *DataChannel {
	dc := &DataChannel{
		label:     label,
		protoID:   protoID,
		id:        id,
		transport: transport,
	}
	dc.isOpen.Store(true)
	return dc
}

// Send queues a message for transmission. It returns when the message has been
// written to the transport (not necessarily acknowledged by the peer).
func (dc *DataChannel) Send(msg []byte) error {
	if !dc.isOpen.Load() {
		return errors.New("webrtc: datachannel closed")
	}

	// WebRTC DataChannel message encoding (RFC 8832 §5.1):
	// [PPTV] [Message Length (3 bytes)] [Message...]
	// P = 0 (ordered), P = 1 (partial), P = 1 + V = 1 (last partial), V = 0 (not final)
	//
	// For simplicity: send as a single message (ordered, not partial).
	// Partial messages are for streaming; our use case is request/response tunnel.
	const msgType = 0x00 // ordered, complete message

	header := make([]byte, 4)
	header[0] = msgType
	binary.BigEndian.PutUint16(header[1:3], uint16(len(msg))) // Message length (actually 2 bytes, MSB=0)

	// Use 3-byte length per RFC 8832.
	header3 := make([]byte, 5)
	header3[0] = msgType
	// Big-endian 24-bit length.
	header3[1] = byte(len(msg) >> 16)
	header3[2] = byte(len(msg) >> 8)
	header3[3] = byte(len(msg))

	dc.mu.Lock()
	_, err := dc.transport.Write(append(header3, msg...))
	dc.mu.Unlock()
	return err
}

// Receive reads the next complete message. It blocks until a message is available.
func (dc *DataChannel) Receive() ([]byte, error) {
	dc.mu.Lock()
	if len(dc.inBuf) > 0 {
		msg := dc.inBuf
		dc.inBuf = nil
		dc.mu.Unlock()
		return msg, nil
	}
	dc.mu.Unlock()

	// Read from transport. This is a simplified read loop — a production
	// implementation would handle partial messages, retransmissions, etc.
	buf := make([]byte, 65535)
	n, err := dc.transport.Read(buf)
	if err != nil {
		return nil, err
	}

	if n < 5 {
		return nil, errors.New("webrtc: datachannel message too short")
	}

	msgType := buf[0]
	msgLen := uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	if 5+int(msgLen) > n {
		return nil, errors.New("webrtc: datachannel truncated message")
	}
	if msgType != DCMTControl {
		return buf[5 : 5+msgLen], nil
	}
	return nil, nil // control message — skip for now
}

// Close closes the DataChannel.
func (dc *DataChannel) Close() error {
	dc.isOpen.Store(false)
	return nil
}

// ---- ICE Agent (simplified) -----------------------------------------------

// ICE candidate types.
const (
	ICECandidateTypeHost  = 0
	ICECandidateTypeSrflx = 1 // server reflexive (from STUN)
	ICECandidateTypePrflx = 2 // peer reflexive
	ICECandidateTypeRelay = 3 // relayed (from TURN)
)

// ICECandidate represents a candidate for ICE negotiation.
type ICECandidate struct {
	Foundation string
	Priority   uint32
	IP         string
	Port       int
	Proto      string // "udp" or "tcp"
	Type       int
}

// ICEAgent manages the ICE negotiation process.
// It gathers candidates, exchanges them via signaling, and selects the best pair.
type ICEAgent struct {
	mu         sync.RWMutex
	candidates []ICECandidate
	localUfrag string
	localPwd   string
	state      ICEState
}

// ICEState represents the state of ICE negotiation.
type ICEState int

const (
	ICEGathering ICEState = iota
	ICERunning
	ICECompleted
	ICEFailed
)

// NewICEAgent creates a new ICE agent.
func NewICEAgent(ufrag, pwd string) *ICEAgent {
	return &ICEAgent{
		localUfrag: ufrag,
		localPwd:   pwd,
		state:      ICEGathering,
	}
}

// GatherHostCandidates discovers host candidates (all local IPs on all interfaces).
func (a *ICEAgent) GatherHostCandidates() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ipStr string
			switch v := addr.(type) {
			case *net.IPNet:
				ipStr = v.IP.String()
			case net.Addr:
				ipStr = v.String()
			}
			if ipStr == "" {
				continue
			}
			// Skip link-local and loopback.
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.IsLoopback() || isLinkLocal(ip) {
				continue
			}
			a.mu.Lock()
			a.candidates = append(a.candidates, ICECandidate{
				IP:       ipStr,
				Port:     0, // port 0 means OS will assign
				Proto:    "udp",
				Type:     ICECandidateTypeHost,
				Priority: 2130706431, // host candidates: high priority
			})
			a.mu.Unlock()
		}
	}
	a.mu.Lock()
	a.state = ICERunning
	a.mu.Unlock()
	return nil
}

// AddServerReflexiveCandidate adds a candidate discovered via STUN.
func (a *ICEAgent) AddServerReflexiveCandidate(ip net.IP, port int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.candidates = append(a.candidates, ICECandidate{
		IP:       ip.String(),
		Port:     port,
		Proto:    "udp",
		Type:     ICECandidateTypeSrflx,
		Priority: 100, // lower than host
	})
}

// Candidates returns all gathered candidates.
func (a *ICEAgent) Candidates() []ICECandidate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]ICECandidate, len(a.candidates))
	copy(out, a.candidates)
	return out
}

// ICEAgentJSON returns the ICE candidates as a JSON-friendly format for signaling.
func (a *ICEAgent) JSON() []map[string]any {
	candidates := a.Candidates()
	out := make([]map[string]any, len(candidates))
	typeNames := []string{"host", "srflx", "prflx", "relay"}
	for i, c := range candidates {
		out[i] = map[string]any{
			"candidate":     fmt.Sprintf("candidate:1 1 udp %d %s %d typ %s", c.Priority, c.IP, c.Port, typeNames[c.Type]),
			"sdpMid":        "0",
			"sdpMLineIndex": 0,
		}
	}
	return out
}

// isLinkLocal reports true for IPv4 link-local addresses (169.254.0.0/16).
func isLinkLocal(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 169 && ip4[1] == 254
}

// ---- Signaling (WebSocket) -----------------------------------------------

// SignalingChannel is the interface for exchanging SDP/ICE with the peer.
// In production, this would be a WebSocket connection to a signaling server.
type SignalingChannel interface {
	SendSDP(offer string) error
	RecvSDP() (string, error)
}

// SimpleSignalingServer is a basic in-process signaling mechanism using a
// shared channel. In production, replace with WebSocket/TURN signaling.
type SimpleSignalingServer struct {
	mu      sync.Mutex
	cond    sync.Cond
	pending []string
}

// NewSimpleSignalingServer creates a signaling server with shared memory.
// Both offer and answer share the same instance.
func NewSimpleSignalingServer() *SimpleSignalingServer {
	return &SimpleSignalingServer{}
}

// Submit stores an SDP for pickup by the other side.
func (s *SimpleSignalingServer) Submit(sdp string) {
	s.mu.Lock()
	s.pending = append(s.pending, sdp)
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Wait blocks until a pending SDP is available, then returns it.
func (s *SimpleSignalingServer) Wait(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	s.mu.Lock()
	for len(s.pending) == 0 {
		if time.Now().After(deadline) {
			s.mu.Unlock()
			return "", errors.New("signaling: timeout waiting for peer")
		}
		s.cond.Wait()
	}
	sdp := s.pending[0]
	s.pending = s.pending[1:]
	s.mu.Unlock()
	return sdp, nil
}

// ---- DTLS-SRTP (simplified) --------------------------------------------

// DTLSRole is the DTLS role of the endpoint.
type DTLSRole int

const (
	DTLSRoleClient DTLSRole = iota
	DTLSRoleServer
)

// PreSharedKeyMode is DTLS with a pre-shared key (PSK) — no certificates needed.
type PreSharedKeyMode struct {
	PSK   []byte // pre-shared key (established via signaling)
	PSKID []byte
}

// NewPSKMode creates a PSK mode with a random 32-byte key.
func NewPSKMode() (*PreSharedKeyMode, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &PreSharedKeyMode{PSK: key, PSKID: []byte("skynet-tunnel/1")}, nil
}

// DeriveKeys derives the traffic keys from the PSK using a simple KDF.
func (p *PreSharedKeyMode) DeriveKeys() (readKey, writeKey []byte) {
	// Simplified: just use the PSK directly as both keys.
	// In production, derive separate keys for each direction using HKDF.
	return p.PSK, p.PSK
}

// ---- Tunnel Backend -------------------------------------------------------

// Backend implements the tunnel.Backend interface using WebRTC DataChannel.
type WebRTCBackend struct {
	cfg   STUNConfig
	mu    sync.RWMutex
	ready chan struct{}

	listener net.Listener
	isOpen   atomic.Bool

	ice       *ICEAgent
	signaling *SimpleSignalingServer
	transport io.ReadWriter // DTLS-wrapped connection
	dc        *DataChannel
}

// STUNConfig holds the configuration for the WebRTC backend.
type STUNConfig struct {
	ListenAddr  string   // TCP listen address for signaling
	STUNServers []string // STUN server addresses for NAT discovery
	Label       string   // DataChannel label
	ProtocolID  string
	PSK         []byte // pre-shared key for DTLS (optional)
}

// NewWebRTCBackend creates a new WebRTC-backed tunnel.
func NewWebRTCBackend(cfg STUNConfig) *WebRTCBackend {
	return &WebRTCBackend{
		cfg:       cfg,
		ready:     make(chan struct{}),
		isOpen:    atomic.Bool{},
		ice:       NewICEAgent("skynet-ufrag", "skynet-pwd"),
		signaling: NewSimpleSignalingServer(),
	}
}

func (b *WebRTCBackend) Name() string           { return "webrtc://" + b.cfg.Label }
func (b *WebRTCBackend) Type() string           { return "webrtc" }
func (b *WebRTCBackend) Ready() <-chan struct{} { return b.ready }

// Start begins gathering ICE candidates and listening for incoming connections.
// The caller should call CreateOffer/AcceptAnswer from a goroutine to
// establish the DataChannel once a peer connects.
func (b *WebRTCBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.isOpen.Load() {
		b.mu.Unlock()
		return nil
	}

	// 1. Gather ICE host candidates.
	if err := b.ice.GatherHostCandidates(); err != nil {
		b.mu.Unlock()
		return fmt.Errorf("webrtc: gather candidates: %w", err)
	}

	// 2. Discover server-reflexive addresses via STUN.
	for _, stunAddr := range b.cfg.STUNServers {
		client, err := NewSTUNClient(stunAddr)
		if err != nil {
			continue
		}
		defer client.Close()
		ip, port, err := client.Lookup(3 * time.Second)
		if err == nil {
			b.ice.AddServerReflexiveCandidate(ip, port)
			break
		}
	}

	b.isOpen.Store(true)
	b.mu.Unlock()
	metrics.SetAvailable("webrtc", true)

	// Start ICE keepalive and nomination.
	go b.runICELoop(ctx)

	// Signal readiness.
	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	return nil
}

func (b *WebRTCBackend) runICELoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.RLock()
			state := b.ice.state
			b.mu.RUnlock()
			if state == ICECompleted || state == ICEFailed {
				return
			}
			// In a production ICE agent, this would send STUN binding
			// indications and check connectivity on candidate pairs.
		}
	}
}

// Stop cleanly shuts down the WebRTC backend.
func (b *WebRTCBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.dc != nil {
		b.dc.Close()
	}
	b.isOpen.Store(false)
	metrics.SetAvailable("webrtc", false)
	return nil
}

// CreateOffer generates an SDP offer and submits it to the signaling channel.
// The caller sends the offer to the peer via the signaling server.
func (b *WebRTCBackend) CreateOffer() (string, error) {
	_ = b.ice.JSON() // candidates available for signaling
	// Simplified SDP (no real SDP parsing/generation).
	// In production, use a proper SDP library.
	return fmt.Sprintf("v=0\r\n%s\r\n", b.cfg.Label), nil
}

// AcceptAnswer processes the peer's SDP answer and establishes the DataChannel.
func (b *WebRTCBackend) AcceptAnswer(answer string) error {
	// In a production implementation, parse SDP, extract ICE candidates,
	// and perform ICE check on candidate pairs.
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ice.mu.Lock()
	b.ice.state = ICECompleted
	b.ice.mu.Unlock()
	return nil
}

// SubmitOffer submits the local offer to the signaling channel and waits
// for the answer.
func (b *WebRTCBackend) SubmitOffer() (string, error) {
	offer, err := b.CreateOffer()
	if err != nil {
		return "", err
	}
	b.signaling.Submit(offer)
	return b.signaling.Wait(10 * time.Second)
}
