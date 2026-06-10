package services

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func testSSHService() *SSHService {
	key := sha256.Sum256([]byte("test-session-secret"))
	return NewSSHService(nil, key, "", "", "", "", false)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	s := testSSHService()
	cases := []string{
		"",
		"hello",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n-----END RSA PRIVATE KEY-----\n",
		strings.Repeat("A", 5000),
	}
	for _, plain := range cases {
		enc, err := s.EncryptSSHKey(plain)
		if err != nil {
			t.Fatalf("EncryptSSHKey(%q) error: %v", plain, err)
		}
		if enc == plain && plain != "" {
			t.Errorf("ciphertext equals plaintext for %q", plain)
		}
		dec, err := s.DecryptSSHKey(enc)
		if err != nil {
			t.Fatalf("DecryptSSHKey error: %v", err)
		}
		if dec != plain {
			t.Errorf("round-trip mismatch: got %q, want %q", dec, plain)
		}
	}
}

func TestEncryptUsesRandomNonce(t *testing.T) {
	s := testSSHService()
	a, _ := s.EncryptSSHKey("same input")
	b, _ := s.EncryptSSHKey("same input")
	if a == b {
		t.Error("two encryptions of the same plaintext produced identical ciphertext (nonce not random)")
	}
}

func TestDecryptRejectsTampered(t *testing.T) {
	s := testSSHService()
	if _, err := s.DecryptSSHKey("not-base64-!!!"); err == nil {
		t.Error("expected error on invalid base64")
	}
	if _, err := s.DecryptSSHKey("YWJj"); err == nil {
		t.Error("expected error on ciphertext shorter than nonce")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	s := testSSHService()
	enc, err := s.EncryptSSHKey("secret payload")
	if err != nil {
		t.Fatal(err)
	}
	other := NewSSHService(nil, sha256.Sum256([]byte("different-secret")), "", "", "", "", false)
	if _, err := other.DecryptSSHKey(enc); err == nil {
		t.Error("decryption with a different key must fail (GCM auth)")
	}
}
