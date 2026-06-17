package webrtc

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// STUN message types (RFC 5389).
const (
	STUNBindingRequest     = 0x0001
	STUNBindingResponse    = 0x0101
	STUNBindingError       = 0x0111
	STUNBindingIndication  = 0x0011

	// STUN attribute types.
	AttrMappedAddress      = 0x0001
	AttrXORMappedAddress   = 0x0020
	AttrUsername           = 0x0006
	AttrMessageIntegrity  = 0x0008
	AttrFingerprint        = 0x8028
	AttrICEControlled      = 0x8029
	AttrICEControlling     = 0x802A
	AttrPriority           = 0x0024
	AttrUseCandidate      = 0x0025
	AttrNetworkInfo        = 0x802F
)

// stunMagicCookie is the RFC 5389 magic cookie value.
const stunMagicCookie = 0x2112A442

// stunMagicCookieXOR returns the XOR mask for the given byte index in IPv6
// XOR-MAPPED-ADDRESS (RFC 5389 §14).
func stunMagicCookieXOR(i int) uint16 {
	cookieBytes := []byte{0x21, 0x12, 0xA4, 0x42}
	idx := (i / 2) % 4
	return uint16(cookieBytes[idx])
}

// STUN message header (20 bytes).
type stunHeader struct {
	Type       uint16
	Length     uint16 // payload length (after header), not including header
	MagicCookie uint32
	TransactionID [12]byte
}

func (h stunHeader) String() string {
	return fmt.Sprintf("STUN type=0x%04X tid=%x", h.Type, h.TransactionID)
}

// STUN attribute header.
type stunAttr struct {
	Type   uint16
	Length uint16
}

// ParseSTUNMessage parses a STUN message from a datagram.
// Returns the message type, transaction ID, and parsed attributes.
func ParseSTUNMessage(data []byte) (msgType uint16, tid [12]byte, attrs map[uint16][]byte, err error) {
	if len(data) < 20 {
		return 0, tid, nil, errors.New("stun: message too short for header")
	}
	hdr := stunHeader{
		Type:        binary.BigEndian.Uint16(data[0:2]),
		Length:      binary.BigEndian.Uint16(data[2:4]),
		MagicCookie: binary.BigEndian.Uint32(data[4:8]),
	}
	if hdr.MagicCookie != stunMagicCookie {
		return 0, tid, nil, errors.New("stun: wrong magic cookie")
	}
	copy(tid[:], data[8:20])

	attrs = make(map[uint16][]byte)
	pos := 20
	for pos+4 <= len(data) && pos-20 < int(hdr.Length) {
		attrType := binary.BigEndian.Uint16(data[pos:])
		attrLen := binary.BigEndian.Uint16(data[pos+2:])
		pad := (attrLen + 3) &^ 3 // 4-byte alignment
		if pos+4+int(pad) > len(data) {
			break
		}
		val := data[pos+4 : pos+4+int(attrLen)]
		attrs[attrType] = val
		pos += 4 + int(pad)
	}
	return hdr.Type, tid, attrs, nil
}

// BuildSTUNBindingRequest creates a STUN Binding Request message.
// Returns the raw UDP payload ready to send to a STUN server.
func BuildSTUNBindingRequest() ([]byte, error) {
	var tid [12]byte
	if _, err := rand.Read(tid[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, 20+4) // header + fingerprint attribute
	binary.BigEndian.PutUint16(msg[0:2], STUNBindingRequest)
	// length: fingerprint attribute = 8 bytes (4 header + 4 value)
	binary.BigEndian.PutUint16(msg[2:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], tid[:])

	// Add FINGERPRINT attribute.
	pos := 20
	binary.BigEndian.PutUint16(msg[pos:], AttrFingerprint)
	binary.BigEndian.PutUint16(msg[pos+2:], 4)
	// CRC32 of the message so far (excluding fingerprint itself)
	crc := crc32Fallback(msg[:pos])
	binary.BigEndian.PutUint32(msg[pos+4:], crc)

	return msg, nil
}

// XORMappedAddress decodes the XOR-MAPPED-ADDRESS attribute (RFC 5389 §14).
func XORMappedAddress(attr []byte, tid [12]byte) (ip net.IP, port int, err error) {
	if len(attr) < 4 {
		return nil, 0, errors.New("stun: xor-mapped-address too short")
	}
	family := binary.BigEndian.Uint16(attr[0:2])
	xPort := binary.BigEndian.Uint16(attr[2:4])

	// XOR with magic cookie and transaction ID.
	xPort ^= uint16(stunMagicCookie >> 16)
	port = int(xPort)

	if family == 0x0001 { // IPv4
		if len(attr) < 8 {
			return nil, 0, errors.New("stun: xor-mapped-address too short for IPv4")
		}
		xIP := binary.BigEndian.Uint32(attr[4:8])
		xIP ^= stunMagicCookie
		ip = net.IP([]byte{
			byte(xIP >> 24), byte(xIP >> 16), byte(xIP >> 8), byte(xIP),
		})
	} else if family == 0x0002 { // IPv6
		if len(attr) < 20 {
			return nil, 0, errors.New("stun: xor-mapped-address too short for IPv6")
		}
		ip = make(net.IP, 16)
		for i := 0; i < 16; i++ {
			x := binary.BigEndian.Uint16(attr[4+i*2 : 6+i*2])
			x ^= uint16(stunMagicCookieXOR(i))
			if i%2 == 0 {
				ip[i] = byte(x >> 8)
			} else {
				ip[i] = byte(x)
			}
		}
	}
	return ip, port, nil
}

// STUNClient is a minimal STUN binding client.
type STUNClient struct {
	Server string // e.g. "stun.l.google.com:19302"
	Conn   net.PacketConn
}

// NewSTUNClient creates a STUN client that sends to the given server address.
func NewSTUNClient(server string) (*STUNClient, error) {
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("stun: listen: %w", err)
	}
	return &STUNClient{Server: server, Conn: conn}, nil
}

// Close releases the STUN client's resources.
func (c *STUNClient) Close() error { return c.Conn.Close() }

// Lookup performs a STUN binding request and returns the server-reflexive
// (public) IP address and port assigned by the NAT.
func (c *STUNClient) Lookup(timeout time.Duration) (net.IP, int, error) {
	req, err := BuildSTUNBindingRequest()
	if err != nil {
		return nil, 0, err
	}

	addr, err := net.ResolveUDPAddr("udp", c.Server)
	if err != nil {
		return nil, 0, fmt.Errorf("stun: resolve %s: %w", c.Server, err)
	}

	c.Conn.SetReadDeadline(time.Now().Add(timeout))
	if _, err := c.Conn.WriteTo(req, addr); err != nil {
		return nil, 0, fmt.Errorf("stun: write: %w", err)
	}

	buf := make([]byte, 512)
	n, _, err := c.Conn.ReadFrom(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("stun: read: %w", err)
	}

	msgType, tid, attrs, err := ParseSTUNMessage(buf[:n])
	if err != nil {
		return nil, 0, err
	}
	if msgType != STUNBindingResponse {
		return nil, 0, fmt.Errorf("stun: unexpected message type 0x%04X", msgType)
	}

	xorAttr := attrs[AttrXORMappedAddress]
	if len(xorAttr) == 0 {
		// Fallback to MAPPED-ADDRESS.
		xorAttr = attrs[AttrMappedAddress]
	}
	if len(xorAttr) == 0 {
		return nil, 0, errors.New("stun: no mapped address in response")
	}

	return XORMappedAddress(xorAttr, tid)
}

// crc32Fallback is a pure-Go CRC32 without external dependencies.
func crc32Fallback(b []byte) uint32 {
	const polynomial = 0xEDB88320
	table := make([]uint32, 256)
	for i := range table {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ polynomial
			} else {
				crc >>= 1
			}
		}
		table[i] = crc
	}
	crc := ^uint32(0)
	for _, v := range b {
		crc = table[byte(crc)^v] ^ (crc >> 8)
	}
	return ^crc
}
