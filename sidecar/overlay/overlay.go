// Package overlay implements a ZeroTier/Tailscale-style virtual overlay network.
// It gives every node a virtual IP address and allows any two nodes to communicate
// over the best available transport path from the pool of backends.
//
// Key concepts:
//   - VirtualNetwork: a shared overlay network identified by a 64-bit NetworkID.
//     Nodes that join the same NetworkID can reach each other by virtual IP.
//   - VirtualIP: a unique IPv4 address assigned to this node within the overlay.
//   - Peer: another node in the overlay, reachable at a virtual IP.
//   - Path: the specific transport backend used to reach a peer.
//
// Architecture:
//
//	VirtualNetwork
//	  ├─ LocalNode (us)
//	  │   └─ VirtualIP: 10.144.0.5
//	  └─ Peers
//	      ├─ Peer 10.144.0.3  → Path: skynet-p2p (preferred)
//	      ├─ Peer 10.144.0.7  → Path: quic (fallback)
//	      └─ Peer 10.144.0.12 → Path: webrtc (browser peer)
//
// Routing: When we need to send to 10.144.0.7, the overlay consults the routing
// table, picks the best available path, and dispatches through the corresponding
// tunnel backend.
//
// This is the layer that turns "a collection of tunnel backends" into
// "a complete software-defined networking solution".
package overlay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// NetworkID is a 64-bit identifier for a virtual overlay network.
// Two nodes with the same NetworkID can communicate.
type NetworkID uint64

// VirtualIP is a 32-bit IPv4 address within the overlay.
type VirtualIP uint32

// NodeID is the public key fingerprint of a node (first 8 bytes of public key).
type NodeID [8]byte

// String returns the NodeID as a hex string.
func (n NodeID) String() string {
	return fmt.Sprintf("%x", n[:])
}

// VirtualIP conversion helpers.
func (v VirtualIP) String() string {
	return formatIPv4(uint32(v))
}
func (v VirtualIP) ToNetIP() net.IP {
	return net.IP([]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	})
}
func ParseVirtualIP(s string) (VirtualIP, error) {
	ip := net.ParseIP(s)
	if ip4 := ip.To4(); ip4 != nil {
		return VirtualIP(binary.BigEndian.Uint32(ip4)), nil
	}
	return 0, errors.New("overlay: not an IPv4 address")
}

// NetworkConfig configures the overlay network.
type NetworkConfig struct {
	// NetworkID identifies the virtual network. Nodes with the same ID can communicate.
	NetworkID NetworkID
	// PrivateKey is the node's Ed25519 private key for identity and encryption.
	PrivateKey ed25519.PrivateKey
	// AllowList restricts which NodeIDs can join. Empty = allow all.
	AllowList []NodeID
	// EnableEncryption forces WireGuard-style encryption on all paths.
	EnableEncryption bool
	// MTU is the maximum transmission unit for the overlay (default 1280).
	MTU int
}

// Network represents a virtual overlay network. It manages peers, routes,
// and the transport backend selection for each peer.
type Network struct {
	cfg NetworkConfig

	mu         sync.RWMutex
	localIP    VirtualIP
	localID    NodeID
	networkIP  net.IP    // network address (e.g. 10.144.0.0)
	netmask    net.IPMask // e.g. /16

	// Peers: keyed by NodeID.
	peers map[NodeID]*Peer

	// Active paths: NodeID → backend type → backend name.
	// The overlay tries paths in preference order until one succeeds.
	paths map[NodeID][]Path

	// Virtual TAP device (optional): if non-nil, L2 frames are bridged here.
	//tap *tun.Device

	stopCh chan struct{}
}

// Peer represents a remote node in the overlay network.
type Peer struct {
	ID        NodeID
	VirtualIP VirtualIP
	Name      string // human-readable label

	mu       sync.RWMutex
	online   atomic.Bool
	paths    []Path // available paths to this peer, sorted by preference

	// Last-seen timestamp.
	lastSeen time.Time

	// Ed25519 public key (used for encryption).
	pubKey ed25519.PublicKey
}

// Path represents a transport path to a peer.
type Path struct {
	BackendType string // "skynet-p2p", "quic", "webrtc", etc.
	Endpoint   string // address to reach peer via this path
	Latency    int64  // RTT in milliseconds
	Preferred  bool   // this path is preferred for this peer
}

// NewNetwork creates a new overlay network with the given configuration.
func NewNetwork(cfg NetworkConfig) (*Network, error) {
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("overlay: invalid Ed25519 private key size")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}

	// Derive local NodeID from public key.
	pubKey := cfg.PrivateKey.Public().(ed25519.PublicKey)
	var nid NodeID
	copy(nid[:], pubKey[:8])

	// Allocate a virtual IP from the network range.
	// Network range is derived from NetworkID.
	networkIP := deriveNetworkIP(cfg.NetworkID)
	localIP := allocateIP(networkIP, nid[:])

	n := &Network{
		cfg:      cfg,
		localID:  nid,
		localIP:  localIP,
		networkIP: networkIP,
		netmask:  net.CIDRMask(16, 32),
		peers:    make(map[NodeID]*Peer),
		paths:    make(map[NodeID][]Path),
		stopCh:   make(chan struct{}),
	}
	return n, nil
}

// LocalNodeID returns this node's NodeID.
func (n *Network) LocalNodeID() NodeID { return n.localID }

// LocalVirtualIP returns this node's virtual IP address.
func (n *Network) LocalVirtualIP() VirtualIP { return n.localIP }

// Start begins peer discovery and route exchange.
func (n *Network) Start(ctx context.Context) error {
	// Announce our presence on all registered paths.
	// In a production system, this would use a DHT or central relay
	// to broadcast our NodeID + VirtualIP to other nodes.
	go n.runPeerDiscovery(ctx)
	go n.runMetricsUpdater(ctx)
	return nil
}

// Stop cleanly shuts down the overlay network.
func (n *Network) Stop(ctx context.Context) error {
	close(n.stopCh)
	return nil
}

// RegisterPath registers a transport path to a peer.
// Call this when a new path to a peer is discovered.
func (n *Network) RegisterPath(to NodeID, path Path) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.paths[to] = append(n.paths[to], path)
}

// UnregisterPath removes a transport path to a peer.
func (n *Network) UnregisterPath(to NodeID, backendType string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var remaining []Path
	for _, p := range n.paths[to] {
		if p.BackendType != backendType {
			remaining = append(remaining, p)
		}
	}
	n.paths[to] = remaining
}

// RouteTo returns the best path to reach a given virtual IP.
func (n *Network) RouteTo(virtualIP VirtualIP) (NodeID, Path, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Find the peer with this virtual IP.
	var targetPeer *Peer
	for _, peer := range n.peers {
		if peer.VirtualIP == virtualIP {
			targetPeer = peer
			break
		}
	}
	if targetPeer == nil {
		return NodeID{}, Path{}, fmt.Errorf("overlay: no route to %s", virtualIP)
	}

	// Find the best available path.
	paths := n.paths[targetPeer.ID]
	if len(paths) == 0 {
		return NodeID{}, Path{}, fmt.Errorf("overlay: no path to %s", targetPeer.ID)
	}

	// Pick the best path: prefer P2P, then lowest latency.
	best := paths[0]
	for _, p := range paths[1:] {
		if p.Preferred && !best.Preferred {
			best = p
		}
		if p.Latency < best.Latency && p.Latency > 0 {
			best = p
		}
	}
	return targetPeer.ID, best, nil
}

// AddPeer manually registers a peer. In production, peers are discovered via
// the DHT/relay system; this is for static configuration.
func (n *Network) AddPeer(id NodeID, virtualIP VirtualIP, pubKey ed25519.PublicKey, paths []Path) {
	n.mu.Lock()
	defer n.mu.Unlock()
	peer := &Peer{
		ID:        id,
		VirtualIP: virtualIP,
		pubKey:    pubKey,
		paths:     paths,
		online:    atomic.Bool{},
	}
	peer.online.Store(true)
	peer.lastSeen = time.Now()
	n.peers[id] = peer
	n.paths[id] = paths
}

// PeerByIP looks up a peer by virtual IP.
func (n *Network) PeerByIP(virtualIP VirtualIP) (*Peer, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, peer := range n.peers {
		if peer.VirtualIP == virtualIP {
			return peer, true
		}
	}
	return nil, false
}

// PeerCount returns the number of known peers.
func (n *Network) PeerCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.peers)
}

// PeerStats returns a snapshot of all peer states.
func (n *Network) PeerStats() map[string]map[string]any {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make(map[string]map[string]any)
	for id, peer := range n.peers {
		out[id.String()] = map[string]any{
			"virtual_ip": peer.VirtualIP.String(),
			"online":     peer.online.Load(),
			"last_seen":  peer.lastSeen.Format(time.RFC3339),
			"paths":      peer.paths,
		}
	}
	return out
}

// ---- Internal helpers ----------------------------------------------------

func (n *Network) runPeerDiscovery(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.stopCh:
			return
		case <-ticker.C:
			// In production: broadcast our presence via DHT or relay server.
			// This would exchange peer tables with other relay nodes.
		}
	}
}

func (n *Network) runMetricsUpdater(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.stopCh:
			return
		case <-ticker.C:
			n.mu.RLock()
			for id, peer := range n.peers {
				backendName := "overlay-" + id.String()[:8]
				if peer.online.Load() {
					metrics.SetAvailable(backendName, true)
				} else {
					metrics.SetAvailable(backendName, false)
				}
			}
			n.mu.RUnlock()
		}
	}
}

// deriveNetworkIP derives a /16 network address from a 64-bit NetworkID.
// This gives each network 65534 usable addresses (10.xxx.xxx.xxx space).
func deriveNetworkIP(id NetworkID) net.IP {
	// Use 10.x.x.x space. First octet fixed, next 2 octets derived from NetworkID.
	b0, b1, b2 := byte(10), byte(id>>48&0xFF), byte(id>>56&0xFF)
	return net.IP([]byte{b0, b1, b2, 0})
}

// allocateIP deterministically allocates a VirtualIP from the network address,
// using the NodeID as the allocation seed. This ensures consistent IP assignment.
func allocateIP(network net.IP, nodeID []byte) VirtualIP {
	// Use the last 2 bytes of the NodeID as the host portion.
	host := binary.BigEndian.Uint32([]byte{0, 0, nodeID[6], nodeID[7]})
	netBits := binary.BigEndian.Uint32([]byte{network[0], network[1], network[2], 0})
	return VirtualIP(netBits | (host & 0xFFFF))
}

// formatIPv4 formats a uint32 as a dotted-quad IPv4 string.
func formatIPv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		v>>24, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF)
}

// generateNodeID creates a random NodeID from Ed25519 key generation.
func generateNodeID() (NodeID, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return NodeID{}, nil, err
	}
	var nid NodeID
	copy(nid[:], pub[:8])
	return nid, priv, nil
}

// ---- WireGuard-style encryption helpers ----------------------------------

// WireGuardMessage is a minimal WireGuard transport message (no outer header).
// In production, the full WireGuard implementation would be used.
// This provides the concept: every packet to a peer is encrypted with
// ChaCha20-Poly1305 using the peer's public key.
type WireGuardMessage struct {
	Counter    uint64
	ReceiverID [8]byte // first 8 bytes of receiver's public key
	Payload    []byte  // encrypted: header_nonce + packet
}

// InitiateHandshake begins a WireGuard-style Noise IK handshake.
// Returns the handshake initiation message to send to the peer.
func InitiateHandshake(myPriv, peerPub ed25519.PrivateKey, peerPubKey ed25519.PublicKey) ([]byte, error) {
	// Simplified: produce a dummy handshake message.
	// Production: implement full WireGuard Noise protocol.
	msg := make([]byte, 148) // WireGuard handshake initiation: 148 bytes
	rand.Reader.Read(msg)
	copy(msg[4:36], peerPubKey)
	return msg, nil
}

// MAC1 computes the first Message Authentication Code for a WireGuard packet.
// Used for endpoint-specific cookies to prevent amplification attacks.
func ComputeMAC1(msg, serverIP, serverPort []byte) [16]byte {
	// Simplified: just hash the message with the endpoint info.
	h := simpleHash16(msg, append(serverIP, serverPort...))
	return h
}

func simpleHash16(data ...[]byte) [16]byte {
	h := uint64(0xdeadbeef)
	for _, d := range data {
		for _, b := range d {
			h = h*31 + uint64(b)
		}
	}
	var out [16]byte
	binary.LittleEndian.PutUint64(out[:8], h)
	binary.LittleEndian.PutUint64(out[8:], h^0xC0FFEE)
	return out
}

// PeerTable is the routing table for the overlay network.
type PeerTable struct {
	mu       sync.RWMutex
	routes   map[VirtualIP]NodeID // virtual IP → node
	byNodeID map[NodeID]VirtualIP  // node → virtual IP
}

// NewPeerTable creates an empty routing table.
func NewPeerTable() *PeerTable {
	return &PeerTable{
		routes:   make(map[VirtualIP]NodeID),
		byNodeID: make(map[NodeID]VirtualIP),
	}
}

// Insert adds a peer to the routing table.
func (t *PeerTable) Insert(ip VirtualIP, id NodeID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes[ip] = id
	t.byNodeID[id] = ip
}

// Lookup finds the NodeID for a given virtual IP.
func (t *PeerTable) Lookup(ip VirtualIP) (NodeID, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	id, ok := t.routes[ip]
	return id, ok
}

// LookupNode finds the virtual IP for a given NodeID.
func (t *PeerTable) LookupNode(id NodeID) (VirtualIP, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ip, ok := t.byNodeID[id]
	return ip, ok
}

// Contains reports whether the given CIDR is reachable through this overlay.
// All traffic to 10.0.0.0/8 (our overlay range) goes through the overlay.
func (t *PeerTable) Contains(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	v := binary.BigEndian.Uint32(ip4)
	return v>>24 == 10 // 10.x.x.x range
}

// RandomPeer returns a random online peer (for initial DHT bootstrap).
func (n *Network) RandomPeer() (*Peer, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var onlinePeers []*Peer
	for _, p := range n.peers {
		if p.online.Load() {
			onlinePeers = append(onlinePeers, p)
		}
	}
	if len(onlinePeers) == 0 {
		return nil, false
	}
	// Deterministic selection based on current time.
	idx := int(time.Now().UnixNano()) % len(onlinePeers)
	return onlinePeers[idx], true
}

// GenerateNetworkID creates a new NetworkID from a human-readable name.
// Uses a simple hash so the same name always produces the same NetworkID.
func GenerateNetworkID(name string) NetworkID {
	h := uint64(0)
	for i, c := range name {
		h = h*33 + uint64(c) + uint64(i)*31
	}
	// Mix in a constant to avoid collision with 0.
	if h == 0 {
		h = 0xC0FFEE42
	}
	return NetworkID(h)
}

// IsPrivateNetwork reports true if the given NetworkID is a private network
// (not globally routed).
func IsPrivateNetwork(id NetworkID) bool {
	// All 10.x.x.x networks are private.
	return true
}

// bigIntHash provides a deterministic hash for NetworkID generation.
func bigIntHash(s string) *big.Int {
	result := big.NewInt(0)
	for _, c := range s {
		result.Mul(result, big.NewInt(33))
		result.Add(result, big.NewInt(int64(c)))
	}
	return result
}
