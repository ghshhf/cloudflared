package webrtc

import (
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// STUN Header
// ---------------------------------------------------------------------------

func TestStunHeaderString(t *testing.T) {
	h := stunHeader{
		Type:          0x0001,
		MagicCookie:   stunMagicCookie,
		TransactionID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}
	s := h.String()
	if len(s) == 0 {
		t.Error("String() should not be empty")
	}
}

// ---------------------------------------------------------------------------
// ParseSTUNMessage
// ---------------------------------------------------------------------------

func buildSTUNMessage(t *testing.T, msgType uint16, attrs map[uint16][]byte) []byte {
	t.Helper()
	total := 20
	for _, v := range attrs {
		total += 4 + len(v)
		pad := (len(v) + 3) & ^3
		total += pad - len(v)
	}
	b := make([]byte, total)
	binary.BigEndian.PutUint16(b[0:2], msgType)
	binary.BigEndian.PutUint16(b[2:4], uint16(total-20))
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	// Random transaction ID.
	tidBytes := make([]byte, 12)
	rand.Read(tidBytes)
	copy(b[8:20], tidBytes)

	pos := 20
	for attrType, val := range attrs {
		pad := (len(val) + 3) & ^3
		binary.BigEndian.PutUint16(b[pos:], attrType)
		binary.BigEndian.PutUint16(b[pos+2:], uint16(len(val)))
		copy(b[pos+4:], val)
		pos += 4 + pad
	}
	return b
}

func TestParseSTUNMessageValid(t *testing.T) {
	data := buildSTUNMessage(t, STUNBindingRequest, map[uint16][]byte{
		AttrMappedAddress: {0x00, 0x01, 0x11, 0x5C, 0x0A, 0x00, 0x00, 0x01},
	})
	msgType, tid, attrs, err := ParseSTUNMessage(data)
	if err != nil {
		t.Fatalf("ParseSTUNMessage: %v", err)
	}
	if msgType != STUNBindingRequest {
		t.Errorf("msgType = 0x%04X; want 0x%04X", msgType, STUNBindingRequest)
	}
	if len(attrs) != 1 {
		t.Errorf("attrs = %d; want 1", len(attrs))
	}
	mapped, ok := attrs[AttrMappedAddress]
	if !ok {
		t.Fatal("MAPPED-ADDRESS attribute not found")
	}
	if len(mapped) != 8 {
		t.Errorf("MAPPED-ADDRESS len = %d; want 8", len(mapped))
	}
	_ = tid // transaction ID present
}

func TestParseSTUNMessageTooShort(t *testing.T) {
	_, _, _, err := ParseSTUNMessage([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for too-short message")
	}
}

func TestParseSTUNMessageWrongCookie(t *testing.T) {
	data := buildSTUNMessage(t, STUNBindingRequest, nil)
	// Corrupt the magic cookie.
	data[5] ^= 0xFF
	_, _, _, err := ParseSTUNMessage(data)
	if err == nil {
		t.Fatal("expected error for wrong magic cookie")
	}
}

func TestParseSTUNMessageNoAttributes(t *testing.T) {
	data := buildSTUNMessage(t, STUNBindingResponse, nil)
	msgType, _, attrs, err := ParseSTUNMessage(data)
	if err != nil {
		t.Fatalf("ParseSTUNMessage: %v", err)
	}
	if msgType != STUNBindingResponse {
		t.Errorf("msgType = 0x%04X; want 0x%04X", msgType, STUNBindingResponse)
	}
	if len(attrs) != 0 {
		t.Errorf("attrs = %d; want 0", len(attrs))
	}
}

func TestParseSTUNMessageMultipleAttributes(t *testing.T) {
	data := buildSTUNMessage(t, STUNBindingRequest, map[uint16][]byte{
		AttrUsername:      []byte("testuser"),
		AttrPriority:      {0x00, 0x00, 0x00, 0x01},
		AttrMappedAddress: {0x00, 0x01, 0x04, 0x00, 0x0A, 0x00, 0x00, 0x01},
	})
	_, _, attrs, err := ParseSTUNMessage(data)
	if err != nil {
		t.Fatalf("ParseSTUNMessage: %v", err)
	}
	if len(attrs) != 3 {
		t.Errorf("attrs = %d; want 3", len(attrs))
	}
}

// ---------------------------------------------------------------------------
// BuildSTUNBindingRequest
// ---------------------------------------------------------------------------

func TestBuildSTUNBindingRequest(t *testing.T) {
	msg, err := BuildSTUNBindingRequest()
	if err != nil {
		t.Fatalf("BuildSTUNBindingRequest: %v", err)
	}
	if len(msg) < 20 {
		t.Fatalf("message too short: %d", len(msg))
	}
	// Verify header.
	msgType := binary.BigEndian.Uint16(msg[0:2])
	if msgType != STUNBindingRequest {
		t.Errorf("msgType = 0x%04X; want 0x%04X", msgType, STUNBindingRequest)
	}
	cookie := binary.BigEndian.Uint32(msg[4:8])
	if cookie != stunMagicCookie {
		t.Errorf("cookie = 0x%08X; want 0x%08X", cookie, stunMagicCookie)
	}
	// Should include a FINGERPRINT attribute.
	if len(msg) < 28 { // 20 header + 8 fingerprint
		t.Errorf("message too short for fingerprint: %d", len(msg))
	}
}

func TestBuildSTUNBindingRequestHasTransactionID(t *testing.T) {
	msg1, _ := BuildSTUNBindingRequest()
	msg2, _ := BuildSTUNBindingRequest()
	// Transaction IDs at bytes 8:20 should be different (random).
	var tid1, tid2 [12]byte
	copy(tid1[:], msg1[8:20])
	copy(tid2[:], msg2[8:20])
	if tid1 == tid2 {
		t.Error("transaction IDs should be random")
	}
}

// ---------------------------------------------------------------------------
// XORMappedAddress
// ---------------------------------------------------------------------------

func TestXORMappedAddressIPv4(t *testing.T) {
	// Build XOR-MAPPED-ADDRESS attribute.
	// Family=0x0001 (IPv4), X-Port, X-Address
	// X-Port = port XOR (magicCookie>>16) = 12345 XOR 0x2112 = 0x3039 ^ 0x2112 = 0x112B
	// X-Address = ip XOR magicCookie
	// ip = 192.168.1.1 → 0xC0A80101
	// X-Address = 0xC0A80101 ^ 0x2112A442 = 0xE1BAA543
	attr := make([]byte, 8)
	binary.BigEndian.PutUint16(attr[0:2], 0x0001)     // IPv4 family
	binary.BigEndian.PutUint16(attr[2:4], 0x112B)     // X-Port
	binary.BigEndian.PutUint32(attr[4:8], 0xE1BAA543) // X-Address

	var tid [12]byte
	ip, port, err := XORMappedAddress(attr, tid)
	if err != nil {
		t.Fatalf("XORMappedAddress: %v", err)
	}
	if port != 12345 {
		t.Errorf("port = %d; want 12345", port)
	}
	if !ip.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("ip = %v; want 192.168.1.1", ip)
	}
}

func TestXORMappedAddressIPv4RoundTrip(t *testing.T) {
	// Construct XOR-MAPPED-ADDRESS and decode it back.
	expectedIP := net.IPv4(10, 20, 30, 40)
	expectedPort := 3478
	var tid [12]byte

	xPort := uint16(expectedPort) ^ uint16(stunMagicCookie>>16)
	xIP := binary.BigEndian.Uint32(expectedIP.To4()) ^ stunMagicCookie

	attr := make([]byte, 8)
	binary.BigEndian.PutUint16(attr[0:2], 0x0001) // IPv4
	binary.BigEndian.PutUint16(attr[2:4], xPort)
	binary.BigEndian.PutUint32(attr[4:8], xIP)

	ip, port, err := XORMappedAddress(attr, tid)
	if err != nil {
		t.Fatalf("XORMappedAddress: %v", err)
	}
	if !ip.Equal(expectedIP) {
		t.Errorf("ip = %v; want %v", ip, expectedIP)
	}
	if port != expectedPort {
		t.Errorf("port = %d; want %d", port, expectedPort)
	}
}

func TestXORMappedAddressTooShort(t *testing.T) {
	_, _, err := XORMappedAddress([]byte{0, 0}, [12]byte{})
	if err == nil {
		t.Fatal("expected error for too-short attribute")
	}
}

func TestXORMappedAddressIPv4TooShort(t *testing.T) {
	_, _, err := XORMappedAddress([]byte{0x00, 0x01, 0x00, 0x00, 0x00}, [12]byte{})
	if err == nil {
		t.Fatal("expected error for too-short IPv4 attribute")
	}
}

func TestXORMappedAddressIPv6PartialData(t *testing.T) {
	// Family=0x0002 (IPv6) but only 4 bytes of address data
	attr := make([]byte, 8)
	binary.BigEndian.PutUint16(attr[0:2], 0x0002) // IPv6
	binary.BigEndian.PutUint16(attr[2:4], 0x0000)
	_, _, err := XORMappedAddress(attr, [12]byte{})
	if err == nil {
		t.Fatal("expected error for too-short IPv6 attribute")
	}
}

// ---------------------------------------------------------------------------
// crc32Fallback
// ---------------------------------------------------------------------------

func TestCRC32Fallback(t *testing.T) {
	c1 := crc32Fallback([]byte("hello"))
	c2 := crc32Fallback([]byte("hello"))
	if c1 != c2 {
		t.Errorf("not deterministic: %d vs %d", c1, c2)
	}
	if c1 == 0 {
		t.Error("CRC32 of non-empty should be non-zero")
	}
}

func TestCRC32FallbackEmpty(t *testing.T) {
	c := crc32Fallback(nil)
	if c != 0 {
		t.Errorf("CRC32 of empty = %d; want 0", c)
	}
}

func TestCRC32FallbackDifferent(t *testing.T) {
	c1 := crc32Fallback([]byte("abc"))
	c2 := crc32Fallback([]byte("xyz"))
	if c1 == c2 {
		t.Error("different inputs should produce different CRCs")
	}
}

// ---------------------------------------------------------------------------
// stunMagicCookieXOR
// ---------------------------------------------------------------------------

func TestStunMagicCookieXOR(t *testing.T) {
	// For byte index 0: cookieBytes[0] = 0x21, idx = (0/2)%4 = 0
	x := stunMagicCookieXOR(0)
	if x != 0x0021 {
		t.Errorf("stunMagicCookieXOR(0) = 0x%04x; want 0x0021", x)
	}
	// For byte index 4: idx = (4/2)%4 = 2, cookieBytes[2] = 0xA4
	x = stunMagicCookieXOR(4)
	if x != 0x00A4 {
		t.Errorf("stunMagicCookieXOR(4) = 0x%04x; want 0x00A4", x)
	}
	// For byte index 6: idx = (6/2)%4 = 3, cookieBytes[3] = 0x42
	x = stunMagicCookieXOR(6)
	if x != 0x0042 {
		t.Errorf("stunMagicCookieXOR(6) = 0x%04x; want 0x0042", x)
	}
}

// ---------------------------------------------------------------------------
// NewWebRTCBackend (constructor only, no network)
// ---------------------------------------------------------------------------

func TestNewWebRTCBackend(t *testing.T) {
	be := NewWebRTCBackend(STUNConfig{
		ListenAddr:  "0.0.0.0:0",
		STUNServers: []string{"stun.l.google.com:19302"},
		Label:       "test-webrtc",
	})
	if be == nil {
		t.Fatal("NewWebRTCBackend returned nil")
	}
	if be.Name() != "webrtc://test-webrtc" {
		t.Errorf("Name = %q; want webrtc://test-webrtc", be.Name())
	}
	if be.Type() != "webrtc" {
		t.Errorf("Type = %q; want webrtc", be.Type())
	}
	if be.Ready() == nil {
		t.Error("Ready() returned nil channel")
	}
}

// ---------------------------------------------------------------------------
// NewDataChannel
// ---------------------------------------------------------------------------

type mockTransport struct {
	readBuf  []byte
	writeBuf []byte
	readErr  error
	writeErr error
}

func (m *mockTransport) Read(p []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n := copy(p, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}

func (m *mockTransport) Write(p []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeBuf = append(m.writeBuf, p...)
	return len(p), nil
}

func TestNewDataChannel(t *testing.T) {
	dc := NewDataChannel("test", "proto1", 0, &mockTransport{})
	if dc == nil {
		t.Fatal("NewDataChannel returned nil")
	}
	if !dc.isOpen.Load() {
		t.Error("DataChannel should be open after creation")
	}
}
