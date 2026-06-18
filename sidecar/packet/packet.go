// Package packet provides zero-dependency (no CGO) implementations of
// fundamental network tunneling protocols. All structures are pure Go and
// self-contained so they can run in constrained environments (containers,
// WASM, sidecars) without elevated privileges.
//
// Implemented protocols:
//
//	GRE   — RFC 2890 Generic Routing Encapsulation
//	VXLAN — RFC 7348 Virtual eXtensible LAN (control plane only; data via UDP)
//	ICMP  — ICMP echo tunneling (ping tunnel, alternative to DNS tunnel)
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"time"
)

// Protocol numbers (IP Protocol field).
const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
	ProtocolGRE  = 47
	ProtocolIPIP = 4
	ProtocolIPv6 = 41
)

// ---- IPv4 header --------------------------------------------------------

// IPv4Header represents a parsed IPv4 header (without options).
// Minimal implementation sufficient for tunnel encapsulation.
type IPv4Header struct {
	Version  uint8 // Version=4
	IHL      uint8 // Internet Header Length in 32-bit words
	TOS      uint8
	TotalLen uint16
	ID       uint16
	FragOff  uint16
	TTL      uint8
	Protocol uint8
	CheckSum uint16 // header checksum (RFC 791)
	SrcIP    net.IP
	DstIP    net.IP
}

// ParseIPv4Header parses an IPv4 header from the given buffer.
// Returns the number of bytes consumed and the payload.
func ParseIPv4Header(b []byte) (hdr IPv4Header, payload []byte, err error) {
	if len(b) < 20 {
		return hdr, nil, errors.New("packet: IPv4 header too short")
	}
	ver := b[0] >> 4
	if ver != 4 {
		return hdr, nil, fmt.Errorf("packet: not IPv4, version=%d", ver)
	}
	ihl := int(b[0] & 0x0F)
	if ihl < 5 || len(b) < ihl*4 {
		return hdr, nil, errors.New("packet: IPv4 header length invalid")
	}
	hdr.Version = ver
	hdr.IHL = uint8(ihl)
	hdr.TOS = b[1]
	hdr.TotalLen = binary.BigEndian.Uint16(b[2:4])
	hdr.ID = binary.BigEndian.Uint16(b[4:6])
	hdr.FragOff = binary.BigEndian.Uint16(b[6:8])
	hdr.TTL = b[8]
	hdr.Protocol = b[9]
	hdr.CheckSum = binary.BigEndian.Uint16(b[10:12])
	hdr.SrcIP = net.IP(b[12:16])
	hdr.DstIP = net.IP(b[16:20])
	hdrLen := ihl * 4
	return hdr, b[hdrLen:], nil
}

// Marshal serializes the IPv4 header back to bytes.
func (h IPv4Header) Marshal() []byte {
	b := make([]byte, 20)
	b[0] = (h.Version << 4) | (h.IHL & 0x0F)
	b[1] = h.TOS
	binary.BigEndian.PutUint16(b[2:4], h.TotalLen)
	binary.BigEndian.PutUint16(b[4:6], h.ID)
	binary.BigEndian.PutUint16(b[6:8], h.FragOff)
	b[8] = h.TTL
	b[9] = h.Protocol
	// CheckSum is written by ComputeChecksum
	binary.BigEndian.PutUint16(b[10:12], h.CheckSum)
	copy(b[12:16], h.SrcIP.To4())
	copy(b[16:20], h.DstIP.To4())
	return b
}

// ComputeChecksum returns the RFC 791 checksum for the header.
func (h IPv4Header) ComputeChecksum() uint16 {
	h2 := h
	h2.CheckSum = 0
	b := h2.Marshal()
	sum := uint32(0)
	for i := 0; i < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

// ---- GRE (RFC 2890) -----------------------------------------------------

// GREHeader represents a GRE header (no checksum, no key, no sequence).
type GREHeader struct {
	Flags    uint8  // Checksum=1, Routing=0, Key=0, Sequence=0, More=1
	Type     uint16 // Ethertype (e.g. 0x0800 for IPv4)
	Checksum uint16 // optional, 0 if not present
	Offset   uint16 // optional
	Key      uint32 // optional
	Sequence uint32 // optional
}

// GRE_MIN_HEADER is the minimum GRE header size (without optional fields).
const GRE_MIN_HEADER = 4

// ParseGRE parses a GRE header and returns the payload.
func ParseGRE(b []byte) (hdr GREHeader, payload []byte, err error) {
	if len(b) < GRE_MIN_HEADER {
		return hdr, nil, errors.New("packet: GRE header too short")
	}
	hdr.Flags = b[0]
	hdr.Type = binary.BigEndian.Uint16(b[2:4])

	offset := GRE_MIN_HEADER
	// Checksum present (bit 0 of flags)
	if hdr.Flags&0x80 != 0 && len(b) >= offset+4 {
		hdr.Checksum = binary.BigEndian.Uint16(b[offset : offset+2])
		hdr.Offset = binary.BigEndian.Uint16(b[offset+2 : offset+4])
		offset += 4
	}
	// Key present (bit 2 of flags)
	if hdr.Flags&0x20 != 0 && len(b) >= offset+4 {
		hdr.Key = binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
	}
	// Sequence present (bit 1 of flags)
	if hdr.Flags&0x40 != 0 && len(b) >= offset+4 {
		hdr.Sequence = binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
	}
	return hdr, b[offset:], nil
}

// Marshal serializes the GRE header, including optional fields when
// the corresponding flag bits are set.
func (g GREHeader) Marshal() []byte {
	b := make([]byte, 4+g.optionalFieldLen())
	b[0] = g.Flags
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], g.Type)

	offset := 4
	if g.Flags&0x80 != 0 { // Checksum + Routing
		binary.BigEndian.PutUint16(b[offset:offset+2], g.Checksum)
		binary.BigEndian.PutUint16(b[offset+2:offset+4], g.Offset)
		offset += 4
	}
	if g.Flags&0x20 != 0 { // Key
		binary.BigEndian.PutUint32(b[offset:offset+4], g.Key)
		offset += 4
	}
	if g.Flags&0x40 != 0 { // Sequence
		binary.BigEndian.PutUint32(b[offset:offset+4], g.Sequence)
		offset += 4
	}
	return b
}

// optionalFieldLen returns the total length of optional GRE fields
// indicated by flag bits.
func (g GREHeader) optionalFieldLen() int {
	n := 0
	if g.Flags&0x80 != 0 {
		n += 4 // Checksum (2) + Offset (2)
	}
	if g.Flags&0x20 != 0 {
		n += 4 // Key
	}
	if g.Flags&0x40 != 0 {
		n += 4 // Sequence
	}
	return n
}

// ---- VXLAN (RFC 7348) --------------------------------------------------

// VXLANHeader represents a VXLAN header.
type VXLANHeader struct {
	Flags     uint8 // 8-bit flags (I flag must be set)
	Reserved  [3]uint8
	VNI       uint32 // 24-bit VXLAN Network Identifier
	Reserved2 uint8
}

// ParseVXLAN parses a VXLAN header from a UDP payload.
func ParseVXLAN(b []byte) (VXLANHeader, []byte, error) {
	if len(b) < 8 {
		return VXLANHeader{}, nil, errors.New("packet: VXLAN header too short")
	}
	h := VXLANHeader{
		Flags:     b[0],
		Reserved:  [3]uint8{b[1], b[2], b[3]},
		VNI:       binary.BigEndian.Uint32(b[4:8]) >> 8,
		Reserved2: b[7],
	}
	return h, b[8:], nil
}

// Marshal serializes a VXLAN header.
func (v VXLANHeader) Marshal() []byte {
	b := make([]byte, 8)
	b[0] = v.Flags | 0x08 // I flag = 1
	b[1], b[2], b[3] = v.Reserved[0], v.Reserved[1], v.Reserved[2]
	// VNI is 24 bits, shifted left 8
	var raw uint32 = v.VNI << 8
	binary.BigEndian.PutUint32(b[4:8], raw)
	b[7] = v.Reserved2
	return b
}

// ---- Packet tunnelling helpers ------------------------------------------

// EncapsulateIPOverGRE wraps an IP packet in a GRE header with an outer IP header.
// This creates a GRE tunnel: inner IP → GRE → outer IP → wire.
func EncapsulateIPOverGRE(innerIP []byte, srcIP, dstIP net.IP, greKey uint32) ([]byte, error) {
	// Parse inner IP header to validate.
	_, _, err := ParseIPv4Header(innerIP)
	if err != nil {
		return nil, err
	}

	// Build GRE header with key.
	gre := GREHeader{
		Flags: 0x20, // Key bit set
		Type:  0x0800,
		Key:   greKey,
	}

	// Outer IP header.
	outer := IPv4Header{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: ProtocolGRE,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		TotalLen: 20 + 4 + uint16(len(innerIP)), // IP + GRE(4) + payload
	}
	outer.CheckSum = outer.ComputeChecksum()
	greBytes := gre.Marshal()

	// Assemble.
	out := make([]byte, 0, int(outer.TotalLen))
	out = append(out, outer.Marshal()...)
	out = append(out, greBytes...)
	out = append(out, innerIP...)
	return out, nil
}

// EncapsulateIPOverUDP wraps an IP packet in a UDP tunnel packet.
// Used by VXLAN and for simple UDP tunneling.
func EncapsulateIPOverUDP(innerIP []byte, srcPort, dstPort uint16, srcIP, dstIP net.IP) ([]byte, error) {
	_, _, err := ParseIPv4Header(innerIP)
	if err != nil {
		return nil, err
	}

	udpLen := 8 + len(innerIP)
	outerLen := 20 + udpLen

	// Outer IPv4 header.
	outer := IPv4Header{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: ProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		TotalLen: uint16(outerLen),
	}
	outer.CheckSum = outer.ComputeChecksum()

	// UDP header (no checksum for simplicity).
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// checksum = 0 (disabled)

	out := make([]byte, 0, outerLen)
	out = append(out, outer.Marshal()...)
	out = append(out, udp...)
	out = append(out, innerIP...)
	return out, nil
}

// EncapsulateOverICMPEcho hides data inside ICMP echo request/reply packets.
// This works in restrictive environments where only ICMP (ping) is allowed.
type ICMPEchoTunnel struct {
	ID     uint16
	Seq    uint16
	Secret uint32
}

// NewICMPEchoTunnel creates a new ICMP echo tunnel with a given secret.
func NewICMPEchoTunnel(secret uint32) *ICMPEchoTunnel {
	return &ICMPEchoTunnel{ID: uint16(secret & 0xFFFF), Seq: 1, Secret: secret}
}

// Encapsulate stores data in an ICMP echo payload.
// The data is XORed with a simple keystream derived from the secret.
func (t *ICMPEchoTunnel) Encapsulate(data []byte) []byte {
	// Simple XOR keystream: repeat 4-byte pattern derived from secret.
	key := make([]byte, len(data))
	pattern := []byte{
		byte(t.Secret >> 24),
		byte(t.Secret >> 16),
		byte(t.Secret >> 8),
		byte(t.Secret),
	}
	for i := range data {
		key[i] = pattern[i%4]
	}

	// XOR encode.
	encoded := make([]byte, len(data))
	for i := range data {
		encoded[i] = data[i] ^ key[i]
	}
	return encoded
}

// Decapsulate reverses Encapsulate.
func (t *ICMPEchoTunnel) Decapsulate(encoded []byte) []byte {
	return t.Encapsulate(encoded) // XOR is symmetric
}

// NextSeq advances the sequence number.
func (t *ICMPEchoTunnel) NextSeq() uint16 {
	seq := t.Seq
	t.Seq++
	return seq
}

// ICMPHeader represents a minimal ICMP header.
type ICMPHeader struct {
	Type     uint8 // 8 = Echo Request, 0 = Echo Reply
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
}

const ICMPHeaderLen = 8

// ParseICMP parses an ICMP header from the given buffer.
func ParseICMP(b []byte) (ICMPHeader, []byte, error) {
	if len(b) < ICMPHeaderLen {
		return ICMPHeader{}, nil, errors.New("packet: ICMP header too short")
	}
	h := ICMPHeader{
		Type:     b[0],
		Code:     b[1],
		Checksum: binary.BigEndian.Uint16(b[2:4]),
		ID:       binary.BigEndian.Uint16(b[4:6]),
		Seq:      binary.BigEndian.Uint16(b[6:8]),
	}
	return h, b[ICMPHeaderLen:], nil
}

// Marshal serializes the ICMP header.
func (c ICMPHeader) Marshal() []byte {
	b := make([]byte, ICMPHeaderLen)
	b[0] = c.Type
	b[1] = c.Code
	binary.BigEndian.PutUint16(b[2:4], c.Checksum)
	binary.BigEndian.PutUint16(b[4:6], c.ID)
	binary.BigEndian.PutUint16(b[6:8], c.Seq)
	return b
}

// ICMPPingChecksum computes the ICMP checksum (RFC 792).
// Handles odd-length buffers by padding with a zero byte per specification.
func ICMPPingChecksum(b []byte) uint16 {
	sum := uint32(0)
	i := 0
	for i+1 < len(b) {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
		i += 2
	}
	// If odd length, pad with zero byte.
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

// PacketStats holds statistics for a tunnel.
type PacketStats struct {
	Sent        uint64
	Received    uint64
	Dropped     uint64
	WrongProto  uint64
	ChecksumErr uint64
	CRCError    uint64
}

// BuildICMPTunnelPacket constructs a full ICMP echo packet with encapsulated data.
func BuildICMPTunnelPacket(t *ICMPEchoTunnel, payload []byte, seq uint16) ([]byte, error) {
	data := t.Encapsulate(payload)
	hdr := ICMPHeader{
		Type: 8, // Echo Request
		Code: 0,
		ID:   t.ID,
		Seq:  seq,
	}
	raw := append(hdr.Marshal(), data...)
	hdr.Checksum = ICMPPingChecksum(raw)
	raw[2] = byte(hdr.Checksum >> 8)
	raw[3] = byte(hdr.Checksum)
	return raw, nil
}

// CRC32C computes CRC32C (Castagnoli) — used by some tunnel integrity checks.
func CRC32C(b []byte) uint32 {
	return crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))
}

// PacketFlow represents a bidirectional tunnel flow.
type PacketFlow struct {
	Seq uint32
	Age time.Time
}

// NewPacketFlow creates a new flow tracker.
func NewPacketFlow() *PacketFlow {
	return &PacketFlow{Seq: 0, Age: time.Now()}
}
