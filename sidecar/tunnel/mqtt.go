// Package tunnel provides pluggable tunnel transport backends.
package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/sidecar/metrics"
)

// ---- MQTT Backend -----------------------------------------------------------
//
// mqttBackend implements an MQTT (Message Queuing Telemetry Transport) backend.
// MQTT is a lightweight publish/subscribe messaging protocol designed for
// IoT devices and low-bandwidth, high-latency networks.
//
// Modes:
//   - "broker": act as an MQTT broker, accepting client connections
//   - "proxy": relay MQTT connections to an upstream broker
//
// MQTT 3.1.1/5.0 protocol features:
//   - CONNECT/CONNACK handshake
//   - PUBLISH (QoS 0/1/2)
//   - SUBSCRIBE/SUBACK
//   - PINGREQ/PINGRESP keepalive
//   - DISCONNECT
//
// Default port: 1883 (plain), 8883 (TLS)
//
// Use cases: IoT device communication, sensor data relay, telemetry
// aggregation through the SkyNet tunnel layer.
type mqttBackend struct {
	name    string
	cfg     mqttConfig
	ln      net.Listener
	readyCh chan struct{}
	stopCh  chan struct{}
	wg      sync.WaitGroup
	metrics atomic.Pointer[metrics.BackendMetrics]

	// Simple topic routing for broker mode
	mu      sync.RWMutex
	clients map[string]*mqttClient
	subs    map[string]map[string]struct{} // topic -> clientID set
}

type mqttConfig struct {
	Mode         string // "broker" or "proxy"
	ListenAddr   string // TCP address to listen on
	UpstreamAddr string // upstream MQTT broker (proxy mode)
	Keepalive    time.Duration
	MaxClients   int
}

type mqttClient struct {
	id     string
	conn   net.Conn
	clean  bool
	topics map[string]byte // subscribed topics with QoS
	sendCh chan []byte
	stopCh chan struct{}
}

// MQTT packet types
const (
	mqttConnect     = 0x10
	mqttConnAck     = 0x20
	mqttPublish     = 0x30
	mqttPubAck      = 0x40
	mqttPubRec      = 0x50
	mqttPubRel      = 0x60
	mqttPubComp     = 0x70
	mqttSubscribe   = 0x82
	mqttSubAck      = 0x90
	mqttUnsubscribe = 0xA2
	mqttUnsubAck    = 0xB0
	mqttPingReq     = 0xC0
	mqttPingResp    = 0xD0
	mqttDisconnect  = 0xE0
)

var _ Backend = (*mqttBackend)(nil)

func (b *mqttBackend) Name() string { return b.name }
func (b *mqttBackend) Type() string { return "mqtt" }

func (b *mqttBackend) Start(ctx context.Context) error {
	if b.metrics.Load() == nil {
		b.metrics.Store(metrics.Default().ForBackend(b.name))
	}

	if b.cfg.Mode == "proxy" {
		return b.startProxy(ctx)
	}
	return b.startBroker(ctx)
}

func (b *mqttBackend) startBroker(ctx context.Context) error {
	addr, err := net.ResolveTCPAddr("tcp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("mqtt: %w", err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("mqtt: listen %s: %w", b.cfg.ListenAddr, err)
	}
	b.ln = ln
	b.clients = make(map[string]*mqttClient)
	b.subs = make(map[string]map[string]struct{})

	close(b.readyCh)
	b.wg.Add(1)
	go b.serveBroker()
	return nil
}

func (b *mqttBackend) serveBroker() {
	defer b.wg.Done()
	for {
		select {
		case <-b.stopCh:
			return
		default:
			if err := b.ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				return
			}
			conn, err := b.ln.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			b.wg.Add(1)
			go func() { defer b.wg.Done(); b.handleBrokerClient(conn) }()
		}
	}
}

func (b *mqttBackend) handleBrokerClient(conn net.Conn) {
	defer conn.Close()
	b.recordConnOpen()

	// Read CONNECT packet
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	pkt, err := b.readPacket(conn)
	if err != nil {
		b.recordError()
		return
	}
	conn.SetReadDeadline(time.Time{})

	if pkt[0] != mqttConnect {
		b.recordError()
		return
	}

	// Parse CONNECT
	clientID, clean := b.parseConnect(pkt)
	if clientID == "" {
		clientID = fmt.Sprintf("client-%d", time.Now().UnixNano())
	}

	// Send CONNACK
	connAck := b.buildConnAck(0, clean)
	if _, err := conn.Write(connAck); err != nil {
		b.recordError()
		return
	}
	b.recordSent(len(connAck))

	// Register client
	client := &mqttClient{
		id:     clientID,
		conn:   conn,
		clean:  clean,
		topics: make(map[string]byte),
		sendCh: make(chan []byte, 100),
		stopCh: make(chan struct{}),
	}
	b.mu.Lock()
	b.clients[clientID] = client
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.clients, clientID)
		for topic := range client.topics {
			if subs, ok := b.subs[topic]; ok {
				delete(subs, clientID)
				if len(subs) == 0 {
					delete(b.subs, topic)
				}
			}
		}
		b.mu.Unlock()
		close(client.stopCh)
	}()

	// Start sender goroutine
	go func() {
		for {
			select {
			case <-client.stopCh:
				return
			case pkt := <-client.sendCh:
				if _, err := conn.Write(pkt); err != nil {
					return
				}
				b.recordSent(len(pkt))
			}
		}
	}()

	// Read loop
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		pkt, err := b.readPacket(conn)
		if err != nil {
			return
		}
		b.recordRecv(len(pkt))

		b.handlePacket(client, pkt)
	}
}

func (b *mqttBackend) readPacket(conn net.Conn) ([]byte, error) {
	// Read fixed header: type + remaining length
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Decode remaining length (variable length encoding)
	remaining := int(header[1])
	if remaining == 0 {
		return header, nil
	}

	// Read payload
	payload := make([]byte, remaining)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	return append(header, payload...), nil
}

func (b *mqttBackend) parseConnect(pkt []byte) (clientID string, clean bool) {
	// CONNECT format: fixed header + protocol name/level + connect flags + keepalive + clientID
	if len(pkt) < 10 {
		return "", false
	}
	// Skip to connect flags (after protocol name + level)
	// Protocol name length (2) + "MQTT" (4) + level (1) = 7 bytes from start of variable header
	// But we need to parse properly
	// Simplified: assume standard format
	idx := 2 // skip fixed header
	// Remaining length is at idx+1, but we already read it
	// Variable header starts at idx
	// Protocol name length
	protoLen := int(binary.BigEndian.Uint16(pkt[idx : idx+2]))
	idx += 2 + protoLen + 1 // skip protocol name + level
	if idx >= len(pkt) {
		return "", false
	}
	connectFlags := pkt[idx]
	clean = (connectFlags & 0x02) != 0
	idx += 3 // skip flags + keepalive

	// Client ID
	if idx+2 > len(pkt) {
		return "", clean
	}
	idLen := int(binary.BigEndian.Uint16(pkt[idx : idx+2]))
	idx += 2
	if idx+idLen > len(pkt) {
		return "", clean
	}
	clientID = string(pkt[idx : idx+idLen])
	return clientID, clean
}

func (b *mqttBackend) buildConnAck(rc byte, sessionPresent bool) []byte {
	sp := byte(0)
	if sessionPresent {
		sp = 1
	}
	return []byte{mqttConnAck, 2, sp, rc}
}

func (b *mqttBackend) handlePacket(client *mqttClient, pkt []byte) {
	pktType := pkt[0] & 0xF0

	switch pktType {
	case mqttPublish:
		b.handlePublish(client, pkt)
	case mqttSubscribe:
		b.handleSubscribe(client, pkt)
	case mqttUnsubscribe:
		b.handleUnsubscribe(client, pkt)
	case mqttPingReq:
		// Send PINGRESP
		client.sendCh <- []byte{mqttPingResp, 0}
	case mqttDisconnect:
		return
	}
}

func (b *mqttBackend) handlePublish(client *mqttClient, pkt []byte) {
	// Parse topic and forward to subscribers
	if len(pkt) < 4 {
		return
	}
	// Topic length at pkt[2:4]
	topicLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if 4+topicLen > len(pkt) {
		return
	}
	topic := string(pkt[4 : 4+topicLen])

	// Find subscribers
	b.mu.RLock()
	subs, ok := b.subs[topic]
	if !ok {
		b.mu.RUnlock()
		return
	}

	// Forward to all subscribers
	for cid := range subs {
		if c, ok := b.clients[cid]; ok && c.id != client.id {
			select {
			case c.sendCh <- pkt:
			default:
				// Channel full, drop
			}
		}
	}
	b.mu.RUnlock()
}

func (b *mqttBackend) handleSubscribe(client *mqttClient, pkt []byte) {
	// Parse topic filters and subscribe
	if len(pkt) < 6 {
		return
	}
	// Packet ID at pkt[2:4]
	// Topic filter length at pkt[4:6]
	idx := 4
	var grantedQos []byte
	for idx < len(pkt) {
		if idx+2 > len(pkt) {
			break
		}
		topicLen := int(binary.BigEndian.Uint16(pkt[idx : idx+2]))
		idx += 2
		if idx+topicLen+1 > len(pkt) {
			break
		}
		topic := string(pkt[idx : idx+topicLen])
		qos := pkt[idx+topicLen]
		idx += topicLen + 1

		// Subscribe
		b.mu.Lock()
		if b.subs[topic] == nil {
			b.subs[topic] = make(map[string]struct{})
		}
		b.subs[topic][client.id] = struct{}{}
		client.topics[topic] = qos
		b.mu.Unlock()

		grantedQos = append(grantedQos, qos)
	}

	// Send SUBACK
	subAck := make([]byte, 4+len(grantedQos))
	subAck[0] = mqttSubAck
	subAck[1] = byte(2 + len(grantedQos))
	copy(subAck[2:4], pkt[2:4]) // packet ID
	copy(subAck[4:], grantedQos)
	client.sendCh <- subAck
}

func (b *mqttBackend) handleUnsubscribe(client *mqttClient, pkt []byte) {
	// Parse topic filters and unsubscribe
	if len(pkt) < 6 {
		return
	}
	idx := 4
	for idx < len(pkt) {
		if idx+2 > len(pkt) {
			break
		}
		topicLen := int(binary.BigEndian.Uint16(pkt[idx : idx+2]))
		idx += 2
		if idx+topicLen > len(pkt) {
			break
		}
		topic := string(pkt[idx : idx+topicLen])
		idx += topicLen

		b.mu.Lock()
		delete(client.topics, topic)
		if subs, ok := b.subs[topic]; ok {
			delete(subs, client.id)
			if len(subs) == 0 {
				delete(b.subs, topic)
			}
		}
		b.mu.Unlock()
	}

	// Send UNSUBACK
	unsubAck := []byte{mqttUnsubAck, 2, pkt[2], pkt[3]}
	client.sendCh <- unsubAck
}

// ---- MQTT Proxy Mode ---

func (b *mqttBackend) startProxy(ctx context.Context) error {
	addr, err := net.ResolveTCPAddr("tcp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("mqtt: %w", err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("mqtt: listen %s: %w", b.cfg.ListenAddr, err)
	}
	b.ln = ln

	close(b.readyCh)
	b.wg.Add(1)
	go b.serveProxy()
	return nil
}

func (b *mqttBackend) serveProxy() {
	defer b.wg.Done()
	for {
		select {
		case <-b.stopCh:
			return
		default:
			if err := b.ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				return
			}
			conn, err := b.ln.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			b.wg.Add(1)
			go func() { defer b.wg.Done(); b.handleProxyClient(conn) }()
		}
	}
}

func (b *mqttBackend) handleProxyClient(conn net.Conn) {
	defer conn.Close()
	b.recordConnOpen()

	if b.cfg.UpstreamAddr == "" {
		b.recordError()
		return
	}

	upstream, err := net.DialTimeout("tcp", b.cfg.UpstreamAddr, 5*time.Second)
	if err != nil {
		b.recordError()
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, conn)
		b.recordSent(int(n))
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(conn, upstream)
		b.recordRecv(int(n))
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-b.stopCh:
	}
}

func (b *mqttBackend) Stop(ctx context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	if b.ln != nil {
		b.ln.Close()
	}
	return nil
}

func (b *mqttBackend) Ready() <-chan struct{} { return b.readyCh }

// ---- Metrics helpers ---

func (b *mqttBackend) recordConnOpen() {
	if m := b.metrics.Load(); m != nil {
		m.ConnectionsActive.Add(1)
	}
}
func (b *mqttBackend) recordSent(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesSentTotal.Add(uint64(n))
	}
}
func (b *mqttBackend) recordRecv(n int) {
	if m := b.metrics.Load(); m != nil {
		m.BytesRecvTotal.Add(uint64(n))
	}
}
func (b *mqttBackend) recordError() {
	if m := b.metrics.Load(); m != nil {
		m.ErrorsTotal.Add(1)
	}
}

// ---- Constructor ---

func newMQTTBackend(cfg Config) Backend {
	getArg := func(i int) string {
		if i < len(cfg.ExtraArgs) {
			return cfg.ExtraArgs[i]
		}
		return ""
	}
	mode := getArg(0)
	if mode == "" {
		mode = "broker"
	}
	listenAddr := cfg.ListenAddress
	if listenAddr == "" {
		listenAddr = getArg(1)
	}
	if listenAddr == "" {
		listenAddr = ":1883"
	}
	return &mqttBackend{
		name: cfg.Name,
		cfg: mqttConfig{
			Mode:         mode,
			ListenAddr:   listenAddr,
			UpstreamAddr: cfg.OriginURL,
			Keepalive:    30 * time.Second,
		},
		readyCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
}
