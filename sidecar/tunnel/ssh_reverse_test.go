package tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// normaliseFingerprint
// ---------------------------------------------------------------------------

func TestNormaliseFingerprint(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"SHA256:abc123", "SHA256:abc123"},
		{"sha256:abc123", "SHA256:abc123"},
		{"abc123", "SHA256:abc123"},
	}
	for _, tc := range tests {
		got := normaliseFingerprint(tc.input)
		if got != tc.want {
			t.Errorf("normaliseFingerprint(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// parseFingerprint
// ---------------------------------------------------------------------------

func TestParseFingerprintValid(t *testing.T) {
	// Generate a real SHA256 hash and base64-encode it.
	hash := sha256.Sum256([]byte("test data"))
	encoded := base64.StdEncoding.EncodeToString(hash[:])
	fp := "SHA256:" + encoded

	raw, err := parseFingerprint(fp)
	if err != nil {
		t.Fatalf("parseFingerprint(%q): %v", fp, err)
	}
	if len(raw) != sha256.Size {
		t.Errorf("raw length = %d; want %d", len(raw), sha256.Size)
	}
}

func TestParseFingerprintTooShort(t *testing.T) {
	_, err := parseFingerprint("SHA256:abc")
	if err == nil {
		t.Fatal("expected error for too-short fingerprint")
	}
}

func TestParseFingerprintInvalidBase64(t *testing.T) {
	_, err := parseFingerprint("SHA256:!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseFingerprintMissingPrefix(t *testing.T) {
	_, err := parseFingerprint("base64data")
	if err == nil {
		t.Fatal("expected error without SHA256: prefix")
	}
}

// ---------------------------------------------------------------------------
// hostKeyCallback — fingerprint match
// ---------------------------------------------------------------------------

func TestHostKeyCallbackFingerprintMatch(t *testing.T) {
	pubKey, fp := testKeyAndFingerprint(t)
	b := &sshReverseBackend{
		name: "test",
		cfg: sshConfig{
			HostKeyFingerprint: fp,
		},
	}

	cb, err := b.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}

	err = cb("testhost", testAddr(), pubKey)
	if err != nil {
		t.Errorf("fingerprint match failed: %v", err)
	}
}

func TestHostKeyCallbackFingerprintMismatch(t *testing.T) {
	pubKey, _ := testKeyAndFingerprint(t)
	b := &sshReverseBackend{
		name: "test",
		cfg: sshConfig{
			HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
	}

	cb, err := b.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}

	err = cb("testhost", testAddr(), pubKey)
	if err == nil {
		t.Fatal("expected error for fingerprint mismatch")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("error = %v; want 'fingerprint mismatch'", err)
	}
}

func TestHostKeyCallbackFingerprintNormalises(t *testing.T) {
	pubKey, fp := testKeyAndFingerprint(t)
	// "sha256:" (lowercase prefix from ssh.FingerprintSHA256) should be
	// normalised to "SHA256:" by hostKeyCallback.
	b := &sshReverseBackend{
		name: "test",
		cfg: sshConfig{
			HostKeyFingerprint: fp, // fp starts with "sha256:"
		},
	}

	cb, err := b.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}

	err = cb("host", testAddr(), pubKey)
	if err != nil {
		t.Errorf("lowercase prefix fingerprint match failed: %v", err)
	}
}

func TestHostKeyCallbackFingerprintRawBase64(t *testing.T) {
	pubKey, fp := testKeyAndFingerprint(t)
	// Without "SHA256:" prefix — should be auto-added.
	raw := fp[7:] // strip "sha256:"
	b := &sshReverseBackend{
		name: "test",
		cfg: sshConfig{
			HostKeyFingerprint: raw, // just the base64 part
		},
	}

	cb, err := b.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}

	err = cb("host", testAddr(), pubKey)
	if err != nil {
		t.Errorf("raw base64 fingerprint match failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// hostKeyCallback — insecure mode
// ---------------------------------------------------------------------------

func TestHostKeyCallbackInsecure(t *testing.T) {
	b := &sshReverseBackend{
		name: "test",
		cfg: sshConfig{
			InsecureSkipVerify: true,
		},
	}

	cb, err := b.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}

	// Should accept any key.
	key := testPublicKey(t)
	err = cb("anyhost", testAddr(), key)
	if err != nil {
		t.Errorf("insecure callback should not reject: %v", err)
	}
}

// ---------------------------------------------------------------------------
// hostKeyCallback — fail closed
// ---------------------------------------------------------------------------

func TestHostKeyCallbackFailClosed(t *testing.T) {
	b := &sshReverseBackend{
		name: "test",
		cfg:  sshConfig{}, // neither fingerprint nor insecure set
	}

	_, err := b.hostKeyCallback()
	if err == nil {
		t.Fatal("expected error: should fail closed when no verification configured")
	}
}

// ---------------------------------------------------------------------------
// newSSHReverseBackend — constructor
// ---------------------------------------------------------------------------

func TestNewSSHReverseBackendDefaults(t *testing.T) {
	be := newSSHReverseBackend(Config{
		Name:      "ssh-test",
		OriginURL: "ssh.example.com:2222",
	})
	if be == nil {
		t.Fatal("newSSHReverseBackend returned nil")
	}
	if be.Name() != "ssh-test" {
		t.Errorf("Name = %q; want ssh-test", be.Name())
	}
	if be.Type() != "ssh-reverse" {
		t.Errorf("Type = %q; want ssh-reverse", be.Type())
	}

	sb, ok := be.(*sshReverseBackend)
	if !ok {
		t.Fatal("not a *sshReverseBackend")
	}
	if sb.cfg.Server != "ssh.example.com:2222" {
		t.Errorf("Server = %q; want ssh.example.com:2222", sb.cfg.Server)
	}
	if sb.cfg.RemotePort != 22 {
		t.Errorf("RemotePort = %d; want 22", sb.cfg.RemotePort)
	}
	// Default: backward compat with old InsecureIgnoreHostKey behavior.
	if !sb.cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should default true for backward compat")
	}
}

func TestNewSSHReverseBackendWithFingerprint(t *testing.T) {
	be := newSSHReverseBackend(Config{
		Name:      "ssh-secure",
		OriginURL: "secure.example.com:22",
		ExtraArgs: []string{
			"secure.example.com:22",
			"admin",
			"",
			"SHA256:ABC123",
			"false",
		},
	})
	sb, ok := be.(*sshReverseBackend)
	if !ok {
		t.Fatal("not a *sshReverseBackend")
	}
	if sb.cfg.HostKeyFingerprint != "SHA256:ABC123" {
		t.Errorf("HostKeyFingerprint = %q; want SHA256:ABC123", sb.cfg.HostKeyFingerprint)
	}
}

// ---------------------------------------------------------------------------
// hostKeyCallback — errSSHNoAuth sentinel
// ---------------------------------------------------------------------------

func TestSSHErrorsDefined(t *testing.T) {
	if errSSHNoAuth == nil {
		t.Fatal("errSSHNoAuth is nil")
	}
	if errSSHParseFingerprint == nil {
		t.Fatal("errSSHParseFingerprint is nil")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testKeyAndFingerprint generates an RSA key pair and returns the public key
// and its SHA256 fingerprint. Uses the same key so fingerprint tests are consistent.
func testKeyAndFingerprint(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	pubKey := signer.PublicKey()
	return pubKey, ssh.FingerprintSHA256(pubKey)
}

// testPublicKey generates an RSA key pair and returns the public key.
func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	return signer.PublicKey()
}

func testAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}
