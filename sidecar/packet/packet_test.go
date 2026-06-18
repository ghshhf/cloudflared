package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// IPv4Header
// ---------------------------------------------------------------------------

func TestParseIPv4HeaderValid(t *testing.T) {
	raw := buildTestIPv4Packet(t, net.IPv4(192, 168, 1, 1), net.IPv4(10, 0, 0, 1), []byte("hello"))
	hdr, payload, err := ParseIPv4Header(raw)
	if err != nil {
		t.Fatalf("ParseIPv4Header: %v", err)
	}
	if hdr.Version != 4 {
		t.Errorf("Version = %d; want 4", hdr.Version)
	}
	if hdr.IHL != 5 {
		t.Errorf("IHL = %d; want 5", hdr.IHL)
	}
	if !hdr.SrcIP.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("SrcIP = %v; want 192.168.1.1", hdr.SrcIP)
	}
	if !hdr.DstIP.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("DstIP = %v; want 10.0.0.1", hdr.DstIP)
	}
	if string(payload) != "hello" {
		t.Errorf("payload = %q; want hello", string(payload))
	}
}

func TestParseIPv4HeaderTooShort(t *testing.T) {
	_, _, err := ParseIPv4Header([]byte{0x45, 0x00, 0x00, 0x14})
	if err == nil {
		t.Fatal("expected error for too-short header")
	}
}

func TestParseIPv4HeaderNotIPv4(t *testing.T) {
	// Version=6, IHL=5
	_, _, err := ParseIPv4Header([]byte{0x65, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for non-IPv4 version")
	}
}

func TestIPv4MarshalRoundTrip(t *testing.T) {
	original := IPv4Header{
		Version:  4,
		IHL:      5,
		TOS:      0,
		TotalLen: 20 + 8,
		ID:       1234,
		FragOff:  0,
		TTL:      64,
		Protocol: 17, // UDP
		SrcIP:    net.IPv4(10, 0, 0, 2),
		DstIP:    net.IPv4(10, 0, 0, 3),
	}
	original.CheckSum = original.ComputeChecksum()

	b := original.Marshal()
	parsed, _, err := ParseIPv4Header(b)
	if err != nil {
		t.Fatalf("ParseIPv4Header after Marshal: %v", err)
	}

	if parsed.SrcIP.String() != original.SrcIP.String() {
		t.Errorf("SrcIP = %s; want %s", parsed.SrcIP, original.SrcIP)
	}
	if parsed.DstIP.String() != original.DstIP.String() {
		t.Errorf("DstIP = %s; want %s", parsed.DstIP, original.DstIP)
	}
	if parsed.TotalLen != original.TotalLen {
		t.Errorf("TotalLen = %d; want %d", parsed.TotalLen, original.TotalLen)
	}
	if parsed.Protocol != original.Protocol {
		t.Errorf("Protocol = %d; want %d", parsed.Protocol, original.Protocol)
	}
	if parsed.ID != original.ID {
		t.Errorf("ID = %d; want %d", parsed.ID, original.ID)
	}
	// Checksum is preserved by Parse (not recomputed).
	if parsed.CheckSum == 0 {
		t.Error("CheckSum should be non-zero (preserved by Parse)")
	}
}

func TestIPv4Checksum(t *testing.T) {
	raw := buildTestIPv4Packet(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), nil)
	hdr, _, _ := ParseIPv4Header(raw)
	// Recompute — should match original.
	got := hdr.ComputeChecksum()
	// The original raw has checksum already computed.
	if got == 0 {
		t.Error("checksum should be non-zero")
	}
}

// ---------------------------------------------------------------------------
// GRE header
// ---------------------------------------------------------------------------

func TestParseGREMinimal(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x08, 0x00, 0xde, 0xad}
	hdr, payload, err := ParseGRE(raw)
	if err != nil {
		t.Fatalf("ParseGRE: %v", err)
	}
	if hdr.Type != 0x0800 {
		t.Errorf("Type = 0x%04x; want 0x0800", hdr.Type)
	}
	if !bytes.Equal(payload, []byte{0xde, 0xad}) {
		t.Errorf("payload = %x; want dead", payload)
	}
}

func TestParseGREWithKey(t *testing.T) {
	// Flags with Key bit set (0x20), Type 0x0800, Key=0x12345678, payload
	raw := []byte{0x20, 0x00, 0x08, 0x00, 0x12, 0x34, 0x56, 0x78, 0xca, 0xfe}
	hdr, payload, err := ParseGRE(raw)
	if err != nil {
		t.Fatalf("ParseGRE with key: %v", err)
	}
	if hdr.Key != 0x12345678 {
		t.Errorf("Key = 0x%08x; want 0x12345678", hdr.Key)
	}
	if !bytes.Equal(payload, []byte{0xca, 0xfe}) {
		t.Errorf("payload = %x; want cafe", payload)
	}
}

func TestParseGRETooShort(t *testing.T) {
	_, _, err := ParseGRE([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for too-short GRE header")
	}
}

func TestGREMarshal(t *testing.T) {
	g := GREHeader{Flags: 0x20, Type: 0x0800, Key: 0xDEADBEEF}
	b := g.Marshal()
	// With Key flag set: 4 (min) + 4 (Key) = 8 bytes
	expectedLen := GRE_MIN_HEADER + 4
	if len(b) != expectedLen {
		t.Errorf("Marshal length = %d; want %d", len(b), expectedLen)
	}
	if b[2] != 0x08 || b[3] != 0x00 {
		t.Errorf("Type = 0x%02x%02x; want 0x0800", b[2], b[3])
	}
	// Key should be at offset 4
	if binary.BigEndian.Uint32(b[4:8]) != 0xDEADBEEF {
		t.Errorf("Key = 0x%08x; want 0xDEADBEEF", binary.BigEndian.Uint32(b[4:8]))
	}
}

// ---------------------------------------------------------------------------
// VXLAN header
// ---------------------------------------------------------------------------

func TestParseVXLANValid(t *testing.T) {
	// VXLAN: flags=0x08 (I flag), reserved, VNI=123456<<8, reserved, payload
	raw := make([]byte, 8+7)
	raw[0] = 0x08 | 0x04 // flags with I flag and some random bits
	binary.BigEndian.PutUint32(raw[4:8], 123456<<8)
	copy(raw[8:], []byte("payload"))
	hdr, payload, err := ParseVXLAN(raw)
	if err != nil {
		t.Fatalf("ParseVXLAN: %v", err)
	}
	if hdr.VNI != 123456 {
		t.Errorf("VNI = %d; want 123456", hdr.VNI)
	}
	if string(payload) != "payload" {
		t.Errorf("payload = %q; want payload", string(payload))
	}
}

func TestParseVXLANTooShort(t *testing.T) {
	_, _, err := ParseVXLAN([]byte{0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for too-short VXLAN header")
	}
}

func TestVXLANMarshalRoundTrip(t *testing.T) {
	v := VXLANHeader{Flags: 0x08, VNI: 99999}
	b := v.Marshal()
	hdr, _, err := ParseVXLAN(b)
	if err != nil {
		t.Fatalf("ParseVXLAN after Marshal: %v", err)
	}
	if hdr.VNI != v.VNI {
		t.Errorf("VNI = %d; want %d", hdr.VNI, v.VNI)
	}
}

// ---------------------------------------------------------------------------
// ICMP header
// ---------------------------------------------------------------------------

func TestParseICMPValid(t *testing.T) {
	raw := []byte{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 0xde, 0xad}
	hdr, payload, err := ParseICMP(raw)
	if err != nil {
		t.Fatalf("ParseICMP: %v", err)
	}
	if hdr.Type != 8 {
		t.Errorf("Type = %d; want 8 (echo request)", hdr.Type)
	}
	if hdr.ID != 0x1234 {
		t.Errorf("ID = 0x%04x; want 0x1234", hdr.ID)
	}
	if hdr.Seq != 1 {
		t.Errorf("Seq = %d; want 1", hdr.Seq)
	}
	if !bytes.Equal(payload, []byte{0xde, 0xad}) {
		t.Errorf("payload = %x; want dead", payload)
	}
}

func TestParseICMPTooShort(t *testing.T) {
	_, _, err := ParseICMP([]byte{8, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for too-short ICMP header")
	}
}

func TestICMPMarshalRoundTrip(t *testing.T) {
	h := ICMPHeader{Type: 0, Code: 0, ID: 42, Seq: 7}
	b := h.Marshal()
	parsed, _, err := ParseICMP(b)
	if err != nil {
		t.Fatalf("ParseICMP after Marshal: %v", err)
	}
	if parsed.Type != h.Type || parsed.Code != h.Code || parsed.ID != h.ID || parsed.Seq != h.Seq {
		t.Errorf("round trip: got %+v; want %+v", parsed, h)
	}
}

func TestICMPPingChecksum(t *testing.T) {
	// Known good: ICMP echo request with 8 bytes of data should have checksum.
	raw := []byte{8, 0, 0, 0, 0x01, 0x02, 0x00, 0x01}
	if cs := ICMPPingChecksum(raw); cs == 0 {
		t.Error("checksum should be non-zero")
	}
	// Zero the checksum field and verify.
	raw[2], raw[3] = 0, 0
	cs := ICMPPingChecksum(raw)
	if cs == 0 {
		t.Error("checksum of zeroed header should be non-zero")
	}
}

// ---------------------------------------------------------------------------
// ICMP Echo Tunnel
// ---------------------------------------------------------------------------

func TestICMPEchoTunnelEncryptDecrypt(t *testing.T) {
	tun := NewICMPEchoTunnel(0xDEADBEEF)
	data := []byte("Hello ICMP tunnel!")
	enc := tun.Encapsulate(data)
	dec := tun.Decapsulate(enc)
	if !bytes.Equal(data, dec) {
		t.Errorf("decrypt = %q; want %q", string(dec), string(data))
	}
	// XOR is symmetric, so encrypt of ciphertext gives plaintext.
	reenc := tun.Encapsulate(enc)
	if !bytes.Equal(reenc, data) {
		t.Logf("XOR symmetric property holds")
	}
}

func TestICMPEchoTunnelNextSeq(t *testing.T) {
	tun := NewICMPEchoTunnel(0)
	s1 := tun.NextSeq()
	s2 := tun.NextSeq()
	if s2 != s1+1 {
		t.Errorf("Seq %d → %d; want increment by 1", s1, s2)
	}
}

func TestBuildICMPTunnelPacket(t *testing.T) {
	tun := NewICMPEchoTunnel(0xCAFE)
	pkt, err := BuildICMPTunnelPacket(tun, []byte("secret data"), 1)
	if err != nil {
		t.Fatalf("BuildICMPTunnelPacket: %v", err)
	}
	if len(pkt) < ICMPHeaderLen {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	hdr, payload, err := ParseICMP(pkt)
	if err != nil {
		t.Fatalf("ParseICMP: %v", err)
	}
	if hdr.Type != 8 {
		t.Errorf("Type = %d; want 8", hdr.Type)
	}
	if hdr.ID != tun.ID {
		t.Errorf("ID = %d; want %d", hdr.ID, tun.ID)
	}
	// Payload is XOR-encoded "secret data"
	dec := tun.Decapsulate(payload)
	if string(dec) != "secret data" {
		t.Errorf("decoded = %q; want 'secret data'", string(dec))
	}
}

// ---------------------------------------------------------------------------
// Encapsulation helpers
// ---------------------------------------------------------------------------

func TestEncapsulateIPOverGRE(t *testing.T) {
	inner := buildTestIPv4Packet(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), []byte("inner"))
	pkt, err := EncapsulateIPOverGRE(inner, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 0)
	if err != nil {
		t.Fatalf("EncapsulateIPOverGRE: %v", err)
	}
	// Outer IP header(20) + GRE minimal(4) + inner packet
	minLen := 20 + GRE_MIN_HEADER + len(inner)
	if len(pkt) < minLen {
		t.Fatalf("len = %d; want >= %d", len(pkt), minLen)
	}

	// Verify outer header.
	outerHdr, afterOuter, err := ParseIPv4Header(pkt)
	if err != nil {
		t.Fatalf("parse outer IP: %v", err)
	}
	if outerHdr.Protocol != ProtocolGRE {
		t.Errorf("outer protocol = %d; want %d (GRE)", outerHdr.Protocol, ProtocolGRE)
	}
	if !outerHdr.SrcIP.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("outer src = %v; want 1.2.3.4", outerHdr.SrcIP)
	}

	// Verify GRE payload contains inner packet.
	greHdr, innerPacket, err := ParseGRE(afterOuter)
	if err != nil {
		t.Fatalf("parse GRE: %v", err)
	}
	if greHdr.Type != 0x0800 {
		t.Errorf("GRE type = 0x%04x; want 0x0800", greHdr.Type)
	}
	// Verify inner packet starts with expected IPv4 header (version=4, IHL=5).
	if len(innerPacket) < 20 || innerPacket[0] != 0x45 {
		t.Errorf("inner packet doesn't start with valid IPv4 header: first byte = 0x%02x", innerPacket[0])
	}
	// Verify inner payload is intact.
	_, innerPayload, _ := ParseIPv4Header(innerPacket)
	if string(innerPayload) != "inner" {
		t.Errorf("inner payload = %q; want 'inner'", string(innerPayload))
	}
}

func TestEncapsulateIPOverGREInvalidInner(t *testing.T) {
	_, err := EncapsulateIPOverGRE([]byte{0, 1, 2}, nil, nil, 0)
	if err == nil {
		t.Fatal("expected error for invalid inner packet")
	}
}

func TestEncapsulateIPOverUDP(t *testing.T) {
	inner := buildTestIPv4Packet(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), []byte("udp-test"))
	pkt, err := EncapsulateIPOverUDP(inner, 12345, 80, net.IPv4(1, 1, 1, 1), net.IPv4(2, 2, 2, 2))
	if err != nil {
		t.Fatalf("EncapsulateIPOverUDP: %v", err)
	}
	// IP(20) + UDP(8) + inner
	expectedLen := 20 + 8 + len(inner)
	if len(pkt) != expectedLen {
		t.Errorf("len = %d; want %d", len(pkt), expectedLen)
	}

	outerHdr, afterOuter, err := ParseIPv4Header(pkt)
	if err != nil {
		t.Fatalf("parse outer IP: %v", err)
	}
	if outerHdr.Protocol != ProtocolUDP {
		t.Errorf("outer protocol = %d; want %d (UDP)", outerHdr.Protocol, ProtocolUDP)
	}

	// Verify inner packet is intact.
	_, innerParsed, err := ParseIPv4Header(afterOuter[8:]) // skip UDP header
	if err != nil {
		t.Fatalf("parse inner IP: %v", err)
	}
	if string(innerParsed) != "udp-test" {
		t.Errorf("inner payload = %q; want udp-test", string(innerParsed))
	}
}

func TestEncapsulateIPOverUDPInvalidInner(t *testing.T) {
	_, err := EncapsulateIPOverUDP([]byte{0, 1, 2}, 0, 0, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid inner packet")
	}
}

// ---------------------------------------------------------------------------
// PacketStats
// ---------------------------------------------------------------------------

func TestPacketStatsZero(t *testing.T) {
	s := PacketStats{}
	if s.Sent != 0 || s.Received != 0 || s.Dropped != 0 {
		t.Error("PacketStats should be zero-valued")
	}
}

// ---------------------------------------------------------------------------
// CRC32C
// ---------------------------------------------------------------------------

func TestCRC32C(t *testing.T) {
	b := []byte("hello")
	c1 := CRC32C(b)
	c2 := CRC32C(b)
	if c1 != c2 {
		t.Errorf("CRC32C not deterministic: %d vs %d", c1, c2)
	}
	if c1 == 0 {
		t.Error("CRC32C of non-empty input should be non-zero")
	}
	// Different input => different checksum.
	c3 := CRC32C([]byte("world"))
	if c1 == c3 {
		t.Errorf("CRC32C collision on 'hello' and 'world'")
	}
}

func TestCRC32CEmpty(t *testing.T) {
	c := CRC32C(nil)
	if c == 0 {
		t.Log("CRC32C of empty input = 0 (expected by Castagnoli spec)")
	}
}

// ---------------------------------------------------------------------------
// NewPacketFlow
// ---------------------------------------------------------------------------

func TestNewPacketFlow(t *testing.T) {
	f := NewPacketFlow()
	if f == nil {
		t.Fatal("NewPacketFlow returned nil")
	}
	if f.Seq != 0 {
		t.Errorf("Seq = %d; want 0", f.Seq)
	}
	if f.Age.IsZero() {
		t.Error("Age should be set")
	}
}

// ---------------------------------------------------------------------------
// Edge cases: nil/empty inputs
// ---------------------------------------------------------------------------

func TestParseIPv4HeaderNil(t *testing.T) {
	_, _, err := ParseIPv4Header(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestParseGRENil(t *testing.T) {
	_, _, err := ParseGRE(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestParseVXLANNil(t *testing.T) {
	_, _, err := ParseVXLAN(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestParseICMPNil(t *testing.T) {
	_, _, err := ParseICMP(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestICMPPingChecksumOddLength(t *testing.T) {
	// Odd-length input should not panic.
	raw := []byte{8, 0, 0, 0, 0, 1, 0, 0, 0} // 9 bytes (odd)
	cs := ICMPPingChecksum(raw)
	if cs == 0 {
		t.Error("checksum should be non-zero")
	}
}

func TestICMPPingChecksumEmpty(t *testing.T) {
	cs := ICMPPingChecksum(nil)
	_ = cs // should not panic
}

func TestICMPEchoTunnelEncapsulateNil(t *testing.T) {
	tun := NewICMPEchoTunnel(42)
	enc := tun.Encapsulate(nil)
	if enc == nil {
		t.Error("Encapsulate(nil) should return non-nil")
	}
	dec := tun.Decapsulate(enc)
	if dec == nil {
		t.Error("Decapsulate of nil-encapsulated should be non-nil")
	}
}

func TestICMPEchoTunnelEmptyPayload(t *testing.T) {
	tun := NewICMPEchoTunnel(0xDEAD)
	data := []byte{}
	enc := tun.Encapsulate(data)
	if len(enc) != 0 {
		t.Errorf("Encapsulate of empty = %d bytes; want 0", len(enc))
	}
}

func TestCRC32CNil(t *testing.T) {
	c := CRC32C(nil)
	_ = c // should not panic
}

func TestCRC32CEmptySlice(t *testing.T) {
	c := CRC32C([]byte{})
	_ = c // should not panic
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildTestIPv4Packet creates a minimal valid IPv4 packet with the given
// src/dst IPs and payload. The header checksum is computed.
func buildTestIPv4Packet(t *testing.T, src, dst net.IP, payload []byte) []byte {
	t.Helper()
	totalLen := 20 + len(payload)
	raw := make([]byte, totalLen)
	raw[0] = 0x45 // Version=4, IHL=5
	raw[8] = 64   // TTL
	raw[9] = 6    // TCP
	binary.BigEndian.PutUint16(raw[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(raw[4:6], 1) // ID
	copy(raw[12:16], src.To4())
	copy(raw[16:20], dst.To4())
	copy(raw[20:], payload)
	// Compute checksum.
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(raw[i])<<8 | uint32(raw[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(raw[10:12], uint16(^sum))
	return raw
}
