package overlay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// VirtualIP
// ---------------------------------------------------------------------------

func TestVirtualIPString(t *testing.T) {
	tests := []struct {
		v    VirtualIP
		want string
	}{
		{VirtualIP(0x0A000001), "10.0.0.1"},
		{VirtualIP(0x0A900001), "10.144.0.1"},
		{VirtualIP(0x0AFFFFFF), "10.255.255.255"},
	}
	for _, tc := range tests {
		got := tc.v.String()
		if got != tc.want {
			t.Errorf("VirtualIP(0x%08x).String() = %q; want %q", uint32(tc.v), got, tc.want)
		}
	}
}

func TestVirtualIPToNetIP(t *testing.T) {
	v := VirtualIP(0x0A0B0C0D)
	ip := v.ToNetIP()
	if !net.IP.Equal(ip, net.IPv4(10, 11, 12, 13)) {
		t.Errorf("ToNetIP = %v; want 10.11.12.13", ip)
	}
}

func TestParseVirtualIP(t *testing.T) {
	v, err := ParseVirtualIP("10.144.0.5")
	if err != nil {
		t.Fatalf("ParseVirtualIP: %v", err)
	}
	if v.String() != "10.144.0.5" {
		t.Errorf("round-trip = %s; want 10.144.0.5", v)
	}
}

func TestParseVirtualIPInvalid(t *testing.T) {
	_, err := ParseVirtualIP("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestParseVirtualIPIPv6(t *testing.T) {
	_, err := ParseVirtualIP("::1")
	if err == nil {
		t.Fatal("expected error for IPv6 address")
	}
}

// ---------------------------------------------------------------------------
// NodeID
// ---------------------------------------------------------------------------

func TestNodeIDString(t *testing.T) {
	var nid NodeID
	for i := range nid {
		nid[i] = byte(i)
	}
	s := nid.String()
	if len(s) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("String length = %d; want 16", len(s))
	}
	if s != "0001020304050607" {
		t.Errorf("String = %q; want 0001020304050607", s)
	}
}

// ---------------------------------------------------------------------------
// NetworkID generate and format
// ---------------------------------------------------------------------------

func TestGenerateNetworkID(t *testing.T) {
	id1 := GenerateNetworkID("test-network")
	id2 := GenerateNetworkID("test-network")
	if id1 != id2 {
		t.Errorf("same name => different IDs: %d vs %d", id1, id2)
	}
}

func TestGenerateNetworkIDDifferent(t *testing.T) {
	id1 := GenerateNetworkID("alpha")
	id2 := GenerateNetworkID("beta")
	if id1 == id2 {
		t.Error("different names should produce different IDs")
	}
}

func TestGenerateNetworkIDNonZero(t *testing.T) {
	id := GenerateNetworkID("")
	if id == 0 {
		t.Errorf("empty string should not produce zero ID, got %d", id)
	}
}

// ---------------------------------------------------------------------------
// IsPrivateNetwork
// ---------------------------------------------------------------------------

func TestIsPrivateNetwork(t *testing.T) {
	if !IsPrivateNetwork(GenerateNetworkID("anything")) {
		t.Error("IsPrivateNetwork should always return true for all 10.x.x.x networks")
	}
}

// ---------------------------------------------------------------------------
// NewNetwork
// ---------------------------------------------------------------------------

func newTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func TestNewNetworkSuccess(t *testing.T) {
	priv := newTestKey(t)
	n, err := NewNetwork(NetworkConfig{
		NetworkID:  12345,
		PrivateKey: priv,
	})
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	if n == nil {
		t.Fatal("NewNetwork returned nil")
	}
	if n.LocalNodeID() == (NodeID{}) {
		t.Error("LocalNodeID is zero")
	}
	if n.LocalVirtualIP() == 0 {
		t.Error("LocalVirtualIP is zero")
	}
}

func TestNewNetworkInvalidKey(t *testing.T) {
	_, err := NewNetwork(NetworkConfig{
		NetworkID:  1,
		PrivateKey: []byte("too-short"),
	})
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestNewNetworkDefaultMTU(t *testing.T) {
	priv := newTestKey(t)
	n, err := NewNetwork(NetworkConfig{
		NetworkID:  1,
		PrivateKey: priv,
	})
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	if n.cfg.MTU != 1280 {
		t.Errorf("MTU = %d; want 1280", n.cfg.MTU)
	}
}

// ---------------------------------------------------------------------------
// AddPeer / PeerByIP / PeerCount / PeerStats
// ---------------------------------------------------------------------------

func TestAddPeerAndLookup(t *testing.T) {
	priv := newTestKey(t)
	n, err := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}

	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	var nid2 NodeID
	copy(nid2[:], pub2[:8])

	n.AddPeer(nid2, VirtualIP(0x0A000002), pub2, nil)

	// By IP.
	peer, ok := n.PeerByIP(VirtualIP(0x0A000002))
	if !ok {
		t.Fatal("PeerByIP returned not found")
	}
	if peer.ID != nid2 {
		t.Errorf("peer ID mismatch")
	}

	// By nonexistent IP.
	_, ok = n.PeerByIP(VirtualIP(0x0A0000FF))
	if ok {
		t.Fatal("PeerByIP should return false for unknown IP")
	}
}

func TestPeerCount(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})

	if n.PeerCount() != 0 {
		t.Errorf("initial PeerCount = %d; want 0", n.PeerCount())
	}

	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	var nid2 NodeID
	copy(nid2[:], pub2[:8])
	n.AddPeer(nid2, VirtualIP(0x0A000002), pub2, nil)

	if n.PeerCount() != 1 {
		t.Errorf("PeerCount = %d; want 1", n.PeerCount())
	}
}

func TestPeerStats(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})

	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	var nid2 NodeID
	copy(nid2[:], pub2[:8])
	n.AddPeer(nid2, VirtualIP(0x0A000002), pub2, nil)

	stats := n.PeerStats()
	if len(stats) != 1 {
		t.Fatalf("PeerStats len = %d; want 1", len(stats))
	}
	for id, s := range stats {
		if s["virtual_ip"] != "10.0.0.2" {
			t.Errorf("peer %s virtual_ip = %v; want 10.0.0.2", id, s["virtual_ip"])
		}
		if s["online"] != true {
			t.Errorf("peer %s online = %v; want true", id, s["online"])
		}
	}
}

// ---------------------------------------------------------------------------
// RouteTo
// ---------------------------------------------------------------------------

func TestRouteToNoPeer(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	_, _, err := n.RouteTo(VirtualIP(0x0A000001))
	if err == nil {
		t.Fatal("expected error for non-existent peer")
	}
}

func TestRouteToNoPath(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	var nid2 NodeID
	copy(nid2[:], pub2[:8])
	n.AddPeer(nid2, VirtualIP(0x0A000002), pub2, nil)

	_, _, err := n.RouteTo(VirtualIP(0x0A000002))
	if err == nil {
		t.Fatal("expected error for peer with no paths")
	}
}

func TestRouteToWithPaths(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	var nid2 NodeID
	copy(nid2[:], pub2[:8])
	paths := []Path{
		{BackendType: "webrtc", Endpoint: "stun:server", Latency: 50, Preferred: false},
		{BackendType: "skynet-p2p", Endpoint: "p2p:peer", Latency: 10, Preferred: true},
	}
	n.AddPeer(nid2, VirtualIP(0x0A000002), pub2, paths)

	// Also register paths separately.
	n.RegisterPath(nid2, paths[0])
	n.RegisterPath(nid2, paths[1])

	nid, path, err := n.RouteTo(VirtualIP(0x0A000002))
	if err != nil {
		t.Fatalf("RouteTo: %v", err)
	}
	if nid != nid2 {
		t.Errorf("node = %v; want %v", nid, nid2)
	}
	// Best path: prefers Preferred=true, then lowest latency.
	if path.Preferred != true {
		t.Errorf("best path should be preferred; got %+v", path)
	}
}

// ---------------------------------------------------------------------------
// Path management
// ---------------------------------------------------------------------------

func TestRegisterAndUnregisterPath(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	var nid2 NodeID
	copy(nid2[:], pub2[:8])

	n.RegisterPath(nid2, Path{BackendType: "quic", Endpoint: "quic:peer"})
	n.RegisterPath(nid2, Path{BackendType: "tcp", Endpoint: "tcp:peer"})

	if len(n.paths[nid2]) != 2 {
		t.Errorf("paths count = %d; want 2", len(n.paths[nid2]))
	}

	n.UnregisterPath(nid2, "quic")
	if len(n.paths[nid2]) != 1 {
		t.Errorf("after unregister, paths count = %d; want 1", len(n.paths[nid2]))
	}
	if n.paths[nid2][0].BackendType != "tcp" {
		t.Errorf("remaining path = %s; want tcp", n.paths[nid2][0].BackendType)
	}
}

// ---------------------------------------------------------------------------
// PeerTable
// ---------------------------------------------------------------------------

func TestNewPeerTable(t *testing.T) {
	pt := NewPeerTable()
	if pt == nil {
		t.Fatal("NewPeerTable returned nil")
	}
}

func TestPeerTableInsertAndLookup(t *testing.T) {
	pt := NewPeerTable()
	var nid NodeID
	copy(nid[:], []byte{0, 1, 2, 3, 4, 5, 6, 7})

	pt.Insert(VirtualIP(0x0A000001), nid)

	got, ok := pt.Lookup(VirtualIP(0x0A000001))
	if !ok {
		t.Fatal("Lookup returned not found")
	}
	if got != nid {
		t.Errorf("Lookup = %v; want %v", got, nid)
	}

	ip, ok := pt.LookupNode(nid)
	if !ok {
		t.Fatal("LookupNode returned not found")
	}
	if ip != VirtualIP(0x0A000001) {
		t.Errorf("LookupNode = %v; want 10.0.0.1", ip)
	}
}

func TestPeerTableLookupNotFound(t *testing.T) {
	pt := NewPeerTable()
	_, ok := pt.Lookup(VirtualIP(0x0A0000FF))
	if ok {
		t.Fatal("Lookup should return false for unknown IP")
	}
	_, ok = pt.LookupNode(NodeID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if ok {
		t.Fatal("LookupNode should return false for unknown node")
	}
}

func TestPeerTableContains(t *testing.T) {
	pt := NewPeerTable()
	if !pt.Contains(net.IPv4(10, 0, 0, 1)) {
		t.Error("10.0.0.1 should be contained")
	}
	if !pt.Contains(net.IPv4(10, 255, 255, 255)) {
		t.Error("10.255.255.255 should be contained")
	}
	if pt.Contains(net.IPv4(192, 168, 1, 1)) {
		t.Error("192.168.1.1 should NOT be contained")
	}
	if pt.Contains(net.IPv4(11, 0, 0, 1)) {
		t.Error("11.0.0.1 should NOT be contained")
	}
}

func TestPeerTableContainsIPv6(t *testing.T) {
	pt := NewPeerTable()
	if pt.Contains(net.ParseIP("::1")) {
		t.Error("IPv6 should NOT be contained")
	}
}

// ---------------------------------------------------------------------------
// RandomPeer
// ---------------------------------------------------------------------------

func TestRandomPeerNoPeers(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	_, ok := n.RandomPeer()
	if ok {
		t.Fatal("RandomPeer should return false when no peers")
	}
}

func TestRandomPeerWithPeers(t *testing.T) {
	priv := newTestKey(t)
	n, _ := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		var nid NodeID
		copy(nid[:], pub[:8])
		n.AddPeer(nid, VirtualIP(0x0A000001+VirtualIP(i)), pub, nil)
	}
	p, ok := n.RandomPeer()
	if !ok {
		t.Fatal("RandomPeer should return a peer")
	}
	if p == nil {
		t.Fatal("RandomPeer returned nil peer")
	}
	if p.VirtualIP == 0 {
		t.Error("RandomPeer returned peer with zero virtual IP")
	}
}

// ---------------------------------------------------------------------------
// generateNodeID
// ---------------------------------------------------------------------------

func TestGenerateNodeID(t *testing.T) {
	nid, priv, err := generateNodeID()
	if err != nil {
		t.Fatalf("generateNodeID: %v", err)
	}
	if nid == (NodeID{}) {
		t.Error("NodeID should not be zero")
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d; want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestGenerateNodeIDUnique(t *testing.T) {
	nid1, _, _ := generateNodeID()
	nid2, _, _ := generateNodeID()
	if nid1 == nid2 {
		t.Error("two generated NodeIDs should be different")
	}
}

// ---------------------------------------------------------------------------
// deriveNetworkIP / allocateIP
// ---------------------------------------------------------------------------

func TestDeriveNetworkIP(t *testing.T) {
	// NetworkID 0x0000900A:
	// b0 = 10
	// b1 = byte(0x0000900A >> 48 & 0xFF) = byte(0) = 0
	// b2 = byte(0x0000900A >> 56 & 0xFF) = byte(0) = 0
	ip := deriveNetworkIP(NetworkID(0x0000900A))
	expected := net.IP([]byte{10, 0, 0, 0})
	if !ip.Equal(expected) {
		t.Errorf("deriveNetworkIP(0x0000900A) = %v; want %v", ip, expected)
	}
}

func TestDeriveNetworkIPDifferent(t *testing.T) {
	// NetworkID with higher bytes set:
	// id = 0x0001_0203_0405_0607
	// b1 = byte(id >> 48) = byte(0x0001) = 0x01
	// b2 = byte(id >> 56) = byte(0x00) = 0x00
	ip := deriveNetworkIP(NetworkID(0x0001020304050607))
	expected := net.IP([]byte{10, 0x01, 0x00, 0})
	if !ip.Equal(expected) {
		t.Errorf("deriveNetworkIP(0x00010203...) = %v; want %v", ip, expected)
	}
}

func TestDeriveNetworkIPConsistent(t *testing.T) {
	ip1 := deriveNetworkIP(NetworkID(42))
	ip2 := deriveNetworkIP(NetworkID(42))
	if !ip1.Equal(ip2) {
		t.Errorf("not deterministic: %v vs %v", ip1, ip2)
	}
}

func TestAllocateIP(t *testing.T) {
	network := net.IP([]byte{10, 0, 0, 0})
	nodeID := []byte{0, 0, 0, 0, 0, 0, 0x01, 0x02}
	ip := allocateIP(network, nodeID)
	if ip.String() != "10.0.1.2" {
		t.Errorf("allocateIP = %s; want 10.0.1.2", ip)
	}
}

func TestAllocateIPConsistent(t *testing.T) {
	network := net.IP([]byte{10, 144, 0, 0})
	nodeID := []byte{0, 0, 0, 0, 0, 0, 0xAB, 0xCD}
	ip1 := allocateIP(network, nodeID)
	ip2 := allocateIP(network, nodeID)
	if ip1 != ip2 {
		t.Errorf("not deterministic: %d vs %d", ip1, ip2)
	}
}

// ---------------------------------------------------------------------------
// WireGuard helpers
// ---------------------------------------------------------------------------

func TestInitiateHandshake(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	msg, err := InitiateHandshake(priv, nil, pub)
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}
	if len(msg) != 148 {
		t.Errorf("handshake message length = %d; want 148", len(msg))
	}
}

func TestComputeMAC1(t *testing.T) {
	mac := ComputeMAC1([]byte("hello"), []byte("192.168.1.1"), []byte{80})
	if mac == ([16]byte{}) {
		t.Error("MAC should not be zero")
	}
}

func TestComputeMAC1Deterministic(t *testing.T) {
	m1 := ComputeMAC1([]byte("test"), []byte("10.0.0.1"), []byte{53})
	m2 := ComputeMAC1([]byte("test"), []byte("10.0.0.1"), []byte{53})
	if m1 != m2 {
		t.Error("MAC should be deterministic")
	}
}

func TestComputeMAC1DifferentInput(t *testing.T) {
	m1 := ComputeMAC1([]byte("msg1"), []byte("host1"), nil)
	m2 := ComputeMAC1([]byte("msg2"), []byte("host2"), nil)
	if m1 == m2 {
		t.Error("different inputs should produce different MACs")
	}
}

// ---------------------------------------------------------------------------
// formatIPv4
// ---------------------------------------------------------------------------

func TestFormatIPv4(t *testing.T) {
	tests := []struct {
		v    uint32
		want string
	}{
		{0x0A000001, "10.0.0.1"},
		{0x0A90000A, "10.144.0.10"},
		{0xFFFFFFFF, "255.255.255.255"},
	}
	for _, tc := range tests {
		got := formatIPv4(tc.v)
		if got != tc.want {
			t.Errorf("formatIPv4(0x%08x) = %q; want %q", tc.v, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Network Start/Stop (basic lifecycle, no panic)
// ---------------------------------------------------------------------------

func TestNetworkStartStop(t *testing.T) {
	priv := newTestKey(t)
	n, err := NewNetwork(NetworkConfig{NetworkID: 1, PrivateKey: priv})
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}

	// Start with a cancellable context to verify no panic.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_ = n.Start(ctx)
	}()

	// Let it run briefly, then stop.
	time.Sleep(50 * time.Millisecond)
	_ = n.Stop(context.Background())
}

// ---------------------------------------------------------------------------
// bigIntHash
// ---------------------------------------------------------------------------

func TestBigIntHash(t *testing.T) {
	h1 := bigIntHash("same")
	h2 := bigIntHash("same")
	if h1.Cmp(h2) != 0 {
		t.Error("bigIntHash not deterministic")
	}
}

// ---------------------------------------------------------------------------
// WireGuardMessage
// ---------------------------------------------------------------------------

func TestWireGuardMessageZero(t *testing.T) {
	msg := WireGuardMessage{}
	if msg.Counter != 0 {
		t.Errorf("Counter = %d; want 0", msg.Counter)
	}
	if msg.ReceiverID != ([8]byte{}) {
		t.Errorf("ReceiverID = %v; want zero", msg.ReceiverID)
	}
	if msg.Payload != nil {
		t.Errorf("Payload = %v; want nil", msg.Payload)
	}
}
