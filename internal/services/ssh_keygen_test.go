package services

import (
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// TestGenerateEd25519Key_RoundTripsThroughChannelParser is the core contract: the
// PEM produced for the goabackup channel MUST re-parse via the SAME gossh.ParsePrivateKey
// path ProxmoxChannel.run() uses, otherwise an in-app-generated key would build a row
// the channel can never load (a silent live-test red with no obvious cause).
func TestGenerateEd25519Key_RoundTripsThroughChannelParser(t *testing.T) {
	k, err := GenerateEd25519Key("goabackup-channel")
	if err != nil {
		t.Fatalf("GenerateEd25519Key error: %v", err)
	}

	if k.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want ed25519", k.KeyType)
	}

	// The private key must be the OpenSSH PEM the channel parses.
	if !strings.HasPrefix(k.PrivateKey, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Errorf("PrivateKey is not an OpenSSH PEM: %.40q", k.PrivateKey)
	}
	signer, err := gossh.ParsePrivateKey([]byte(k.PrivateKey))
	if err != nil {
		t.Fatalf("ParsePrivateKey (channel path) rejected the generated key: %v", err)
	}

	// The authorized_keys line must be the single-line ed25519 public form, and it
	// must correspond to the very private key generated (same wire bytes).
	if !strings.HasPrefix(k.PublicKey, "ssh-ed25519 ") {
		t.Errorf("PublicKey is not an ed25519 authorized_keys line: %q", k.PublicKey)
	}
	if strings.Contains(k.PublicKey, "\n") {
		t.Errorf("PublicKey must be a single line, got a multiline value: %q", k.PublicKey)
	}
	parsedPub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(k.PublicKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey rejected the generated public line: %v", err)
	}
	if got := string(signer.PublicKey().Marshal()); got != string(parsedPub.Marshal()) {
		t.Error("public line does not match the private key's public half (mismatched pair)")
	}
}

// TestGenerateEd25519Key_FingerprintMatchesPublicKey verifies the displayed
// fingerprint is the SHA256 of the actual public key (the value an admin compares
// against `ssh-keygen -lf`), not a stale/independent string.
func TestGenerateEd25519Key_FingerprintMatchesPublicKey(t *testing.T) {
	k, err := GenerateEd25519Key("goabackup-channel")
	if err != nil {
		t.Fatalf("GenerateEd25519Key error: %v", err)
	}
	if !strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint is not SHA256 form: %q", k.Fingerprint)
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(k.PublicKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if want := gossh.FingerprintSHA256(pub); want != k.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q (does not match the served public key)", k.Fingerprint, want)
	}
}

// TestGenerateEd25519Key_KeysAreUnique guards against a constant/seeded generator:
// two calls must yield two distinct private keys and fingerprints.
func TestGenerateEd25519Key_KeysAreUnique(t *testing.T) {
	a, err := GenerateEd25519Key("a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateEd25519Key("b")
	if err != nil {
		t.Fatal(err)
	}
	if a.PrivateKey == b.PrivateKey {
		t.Error("two generations produced identical private keys")
	}
	if a.Fingerprint == b.Fingerprint {
		t.Error("two generations produced identical fingerprints")
	}
}
