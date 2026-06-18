// Package tunnel provides pluggable tunnel transport backends.
package tunnel

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// ---- DNS Tunnel Backend --------------------------------------------------

// dnsTunnelBackend implements a DNS-over-DNS tunnel (similar to iodine, dnscat2).
// It encodes arbitrary data as subdomains and sends them as DNS queries to a
// recursive DNS server that forwards to our tunnel resolver.
//
// Encoding scheme (compatible with the iodine protocol):
//   subdomain = "<base32(data)[:8]>.<tunnel_domain>"
//   e.g.  MFRGGZDFMZTWU3LNBAMIYTSLFQ======.tunnel.example.com.
//
// Each query carries ~37 bytes of payload (40 - overhead).
// Responses carry data in TXT/A records.
//
// This works in the most restrictive network environments:
// - Only port 53/UDP needs to be open (almost always allowed)
// - No HTTP/HTTPS requirement
// - Works through most captive portals
//
// Use case: Corporate networks, hotel WiFi, countries that block everything
// except DNS.
type dnsTunnelBackend struct {
	cfg Config

	mu      sync.Mutex
	conn    net.Conn // UDP connection to DNS server
	ready   chan struct{}
	started bool
	stopped bool

	// Tunnel domain (the authoritative zone we control).
	tunnelDomain string
	// Encoder: base32 for lowercase compatibility.
	enc *base32.Encoding
	// Sequence number for ordering.
	seq uint32
}

// newDNSTunnelBackend creates a DNS tunnel backend.
func newDNSTunnelBackend(cfg Config) *dnsTunnelBackend {
	return &dnsTunnelBackend{
		cfg:          cfg,
		ready:        make(chan struct{}),
		enc:          base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567"),
		tunnelDomain: cfg.TunnelDomain,
	}
}

func (b *dnsTunnelBackend) Name() string           { return "dns-tunnel://" + b.cfg.Name }
func (b *dnsTunnelBackend) Type() string           { return "dns-tunnel" }
func (b *dnsTunnelBackend) Ready() <-chan struct{} { return b.ready }

func (b *dnsTunnelBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	// Connect to DNS server (recursive resolver or our tunnel resolver).
	dnsServer := b.cfg.RelayTarget
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53" // default: Google DNS
	}

	conn, err := net.DialTimeout("udp", dnsServer, 10*time.Second)
	if err != nil {
		b.mu.Unlock()
		metrics.SetAvailable("dns-tunnel", false)
		return fmt.Errorf("dns-tunnel: dial %s: %w", dnsServer, err)
	}

	b.conn = conn
	b.started = true
	b.mu.Unlock()

	metrics.SetAvailable("dns-tunnel", true)
	go b.recvLoop(ctx)

	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	return nil
}

// recvLoop handles incoming DNS responses.
func (b *dnsTunnelBackend) recvLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		b.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := b.conn.(net.PacketConn).ReadFrom(buf)
		if err != nil {
			if b.stopped || ctx.Err() != nil {
				return
			}
			continue
		}

		// Parse DNS response.
		data := b.parseDNSResponse(buf[:n])
		if len(data) > 0 {
			metrics.RecordTransfer("dns-tunnel", 0, int64(len(data)))
			// Forward to origin.
			b.forwardToOrigin(data)
		}
	}
}

// parseDNSResponse extracts tunneled data from a DNS response.
// It looks for TXT records (most common for tunnel data) or CNAME chains.
func (b *dnsTunnelBackend) parseDNSResponse(resp []byte) []byte {
	if len(resp) < 12 {
		return nil
	}

	// DNS header: 12 bytes.
	flags := binary.BigEndian.Uint16(resp[2:4])
	// QR=1 (response), AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
	if flags&0x8000 == 0 {
		return nil // Not a response.
	}
	qdCount := binary.BigEndian.Uint16(resp[4:6])
	if qdCount == 0 {
		return nil
	}
	_ = qdCount // consumed header

	// Skip question section to get to answer section.
	pos := 12
	for i := 0; i < int(qdCount) && pos < len(resp); i++ {
		pos = b.skipDNSName(resp, pos)
		if pos+4 > len(resp) {
			return nil
		}
		pos += 4 // QTYPE + QCLASS
	}

	// Parse answer records.
	var out []byte
	for pos < len(resp) {
		// Skip name (could be pointer or inline).
		pos = b.skipDNSName(resp, pos)
		if pos+10 > len(resp) {
			break
		}
		rrType := binary.BigEndian.Uint16(resp[pos:])
		pos += 8                                // TYPE + CLASS
		_ = binary.BigEndian.Uint32(resp[pos:]) // TTL
		pos += 4
		rdLen := int(binary.BigEndian.Uint16(resp[pos:]))
		pos += 2
		if pos+rdLen > len(resp) {
			break
		}
		rdata := resp[pos : pos+rdLen]
		pos += rdLen

		// TXT record: type 16
		if rrType == 16 && len(rdata) > 1 {
			txtLen := int(rdata[0])
			if txtLen > 0 && len(rdata) >= txtLen+1 {
				out = append(out, rdata[1:txtLen+1]...)
			}
		}
		// CNAME chain: type 5 — extract from name encoding.
		if rrType == 5 && len(rdata) > 0 {
			cname := b.extractCNAMESubdomain(rdata)
			if cname != "" {
				out = append(out, []byte(cname)...)
			}
		}
	}
	return out
}

func (b *dnsTunnelBackend) skipDNSName(msg []byte, pos int) int {
	for pos < len(msg) {
		length := int(msg[pos])
		if length == 0 {
			return pos + 1
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer: skip it and return.
			return pos + 2
		}
		pos += length + 1
	}
	return len(msg)
}

func (b *dnsTunnelBackend) extractCNAMESubdomain(rdata []byte) string {
	// Simple CNAME: extract first label if it looks like base32.
	if len(rdata) < 2 || rdata[0] == 0 || rdata[0] > 63 {
		return ""
	}
	length := int(rdata[0])
	if length > len(rdata)-1 {
		length = len(rdata) - 1
	}
	label := string(rdata[1 : 1+length])
	// Valid base32 chars for our encoding.
	for _, c := range label {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return ""
		}
	}
	return label
}

// SendData encodes data as DNS queries and sends them to the DNS server.
// Each query carries a chunk of data in the subdomain.
func (b *dnsTunnelBackend) SendData(data []byte) error {
	if b.conn == nil {
		return errors.New("dns-tunnel: not connected")
	}

	// Split data into chunks that fit in subdomains.
	// Each chunk: 8 chars of base32 = 5 bytes of data.
	const chunkSize = 5
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		// Pad to 5 bytes for base32.
		padded := make([]byte, chunkSize)
		copy(padded, chunk)
		encoded := b.enc.EncodeToString(padded)
		// Remove padding.
		encoded = strings.TrimRight(encoded, "=")

		// Build DNS query.
		query := b.buildDNSQuery(encoded)
		if _, err := b.conn.Write(query); err != nil {
			metrics.RecordError("dns-tunnel")
			return err
		}
	}
	return nil
}

// buildDNSQuery creates a DNS query for the given subdomain.
func (b *dnsTunnelBackend) buildDNSQuery(subdomain string) []byte {
	// DNS header (12 bytes) + query name + query type/class.
	// Transaction ID: random.
	txID := uint16(rand.Int63() & 0xFFFF)

	// Build the full query name.
	var name []byte
	for _, label := range strings.Split(subdomain, ".") {
		name = append(name, byte(len(label)))
		name = append(name, label...)
	}
	name = append(name, 0) // null terminator

	// Build full DNS query name with length-prefixed labels.
	var fullName []byte
	labels := strings.Split(subdomain, ".")
	for _, l := range labels {
		fullName = append(fullName, byte(len(l)))
		fullName = append(fullName, []byte(l)...)
	}
	fullName = append(fullName, byte(len(b.tunnelDomain)))
	fullName = append(fullName, []byte(b.tunnelDomain)...)
	fullName = append(fullName, 0)

	msgLen := 12 + len(fullName) + 4
	msg := make([]byte, msgLen)

	// Header.
	binary.BigEndian.PutUint16(msg[0:2], txID)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // flags: standard query
	binary.BigEndian.PutUint16(msg[4:6], 1)      // 1 question
	binary.BigEndian.PutUint16(msg[6:8], 0)      // 0 answers
	binary.BigEndian.PutUint16(msg[8:10], 0)     // 0 authority
	binary.BigEndian.PutUint16(msg[10:12], 0)    // 0 additional

	// Question section.
	copy(msg[12:], fullName)
	pos := 12 + len(fullName)
	binary.BigEndian.PutUint16(msg[pos:pos+2], 16)  // TXT record
	binary.BigEndian.PutUint16(msg[pos+2:pos+4], 1) // class: IN

	return msg
}

func (b *dnsTunnelBackend) forwardToOrigin(data []byte) {
	if b.cfg.OriginURL == "" {
		return
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", b.cfg.OriginURL)
	if err != nil {
		return
	}
	defer conn.Close()
	io.Copy(conn, strings.NewReader(string(data)))
}

func (b *dnsTunnelBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{})
	metrics.SetAvailable("dns-tunnel", false)
	return nil
}

// ---- ICMP Tunnel Backend ------------------------------------------------

// icmpTunnelBackend implements an ICMP echo tunnel (ping tunnel).
// Data is hidden in the payload of ICMP echo request/reply packets.
// This works when ONLY ping (ICMP echo) is allowed out of the network.
//
// The tunnel uses a simple XOR keystream cipher with a shared secret,
// compatible with ptunnel-ng style encoding.
//
// Use case: Networks that block all UDP and TCP but allow ICMP (ping).
type icmpTunnelBackend struct {
	cfg Config

	mu      sync.Mutex
	conn    *net.IPConn // Raw IP socket for ICMP
	ready   chan struct{}
	started bool
	stopped bool

	// Shared secret for XOR keystream.
	secret uint32
	// Local echo ID for identification.
	echoID  uint16
	echoSeq atomic.Uint32
}

// newICMPTunnelBackend creates an ICMP tunnel backend.
func newICMPTunnelBackend(cfg Config) *icmpTunnelBackend {
	return &icmpTunnelBackend{
		cfg:     cfg,
		ready:   make(chan struct{}),
		secret:  0xDEADBEEF,
		echoID:  uint16(cfg.GREKey & 0xFFFF), // derive from GREKey if set
		echoSeq: atomic.Uint32{},
	}
}

func (b *icmpTunnelBackend) Name() string           { return "icmp-tunnel://" + b.cfg.Name }
func (b *icmpTunnelBackend) Type() string           { return "icmp-tunnel" }
func (b *icmpTunnelBackend) Ready() <-chan struct{} { return b.ready }

// BuildICMPEchoRequest builds an ICMP echo request packet with tunneled data.
func (b *icmpTunnelBackend) BuildICMPEchoRequest(payload []byte) ([]byte, error) {
	return b.buildICMPPacket(8, payload)
}

func (b *icmpTunnelBackend) buildICMPPacket(msgType uint8, payload []byte) ([]byte, error) {
	seq := uint16(b.echoSeq.Add(1))
	// ICMP header: type(1) + code(1) + checksum(2) + id(2) + seq(2) = 8 bytes.
	header := make([]byte, 8)
	header[0] = msgType
	header[1] = 0
	header[2] = 0 // checksum placeholder
	header[3] = 0
	binary.BigEndian.PutUint16(header[4:6], b.echoID)
	binary.BigEndian.PutUint16(header[6:8], seq)

	// XOR-encrypt the payload using the keystream.
	encrypted := b.xorPayload(payload)

	// Build full packet.
	full := append(header, encrypted...)

	// Compute ICMP checksum (RFC 792).
	full[2] = 0
	full[3] = 0
	checksum := icmpChecksum(full)
	full[2] = byte(checksum >> 8)
	full[3] = byte(checksum)

	return full, nil
}

func (b *icmpTunnelBackend) xorPayload(data []byte) []byte {
	// 4-byte XOR keystream derived from secret.
	pattern := []byte{
		byte(b.secret >> 24),
		byte(b.secret >> 16),
		byte(b.secret >> 8),
		byte(b.secret),
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ pattern[i%4]
	}
	return out
}

// icmpChecksum computes the ICMP checksum (RFC 792).
func icmpChecksum(msg []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(msg); i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func (b *icmpTunnelBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}

	// Use the ICMP echo packet type which doesn't need special privileges.
	// Note: On Linux, this requires CAP_NET_RAW or running as root.
	// The "datagram" mode uses SOCK_DGRAM which doesn't need raw sockets.
	conn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		b.mu.Unlock()
		metrics.SetAvailable("icmp-tunnel", false)
		return fmt.Errorf("icmp-tunnel: listen: %w", err)
	}

	b.conn = conn
	b.started = true
	b.mu.Unlock()

	metrics.SetAvailable("icmp-tunnel", true)
	go b.recvLoop(ctx)

	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	return nil
}

func (b *icmpTunnelBackend) recvLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		b.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := b.conn.ReadFromIP(buf)
		if err != nil {
			if b.stopped || ctx.Err() != nil {
				return
			}
			continue
		}

		_ = addr // peer address

		// Parse ICMP header.
		if n < 8 {
			continue
		}
		icmpType := buf[0]
		if icmpType != 0 && icmpType != 8 {
			continue // Not an echo request/reply.
		}
		id := binary.BigEndian.Uint16(buf[4:6])
		if id != b.echoID {
			continue // Not our tunnel.
		}

		// Decrypt payload.
		encrypted := buf[8:n]
		decrypted := b.xorPayload(encrypted)

		// Send to origin.
		metrics.RecordTransfer("icmp-tunnel", 0, int64(len(decrypted)))
		b.forwardToOrigin(decrypted)
	}
}

func (b *icmpTunnelBackend) forwardToOrigin(data []byte) {
	if b.cfg.OriginURL == "" {
		return
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", b.cfg.OriginURL)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write(data)
}

func (b *icmpTunnelBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}
	b.started = false
	b.stopped = true
	b.ready = make(chan struct{})
	metrics.SetAvailable("icmp-tunnel", false)
	return nil
}
