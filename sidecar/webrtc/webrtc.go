// Package webrtc implements a WebRTC DataChannel backend for the tunnel
// package. It provides a browser-native P2P channel: a web page can connect
// directly to this tunnel using the standard WebRTC RTCPeerConnection API,
// without any plugins or native clients.
//
// WebRTC is especially valuable when the client is a browser on a restrictive
// network — ICE + STUN/TURN handle NAT traversal automatically, and DTLS
// provides encryption without certificates on either side (using DTLS-SRTP
// pre-shared key mode).
//
// Architecture:
//
//	Browser RTCPeerConnection
//	  ↕ DTLS handshake (keyed via signaling)
//	  ↕ ICE candidate exchange (STUN server provides reflexive address)
//	  ↕ UDP (or TCP via TURN relay)
//	  ↕ webrtcBackend (this package)
//	       ↕ tunnel origin
//
// Key files:
//   - webrtc.go   — RTCPeerConnection wrapper, signaling, data channel
//   - ice.go      — ICE agent: candidate gathering, pair nomination, keepalive
//   - stun.go     — STUN client: binding requests/responses, XOR-mapped address
package webrtc
