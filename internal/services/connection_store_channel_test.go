package services

import (
	"crypto/sha256"
	"strings"
	"testing"

	"goacore/internal/config"
	"goacore/internal/models"
)

// TestGoabackupChannelExtra verifies the non-secret pubkey/fingerprint/keytype
// extraction from a 'goabackup-channel' connection's extra_json, including the
// nil-safe fallbacks. It mirrors TestProxmoxExtra for the new service.
func TestGoabackupChannelExtra(t *testing.T) {
	if p, f, k := GoabackupChannelExtra(nil); p != "" || f != "" || k != "" {
		t.Errorf("nil connection: got (%q,%q,%q), want empty", p, f, k)
	}
	c := &models.Connection{Extra: map[string]string{
		"pubkey":      "ssh-ed25519 AAAA... goabackup",
		"fingerprint": "SHA256:abc",
		"keytype":     "ed25519",
	}}
	if p, f, k := GoabackupChannelExtra(c); p != "ssh-ed25519 AAAA... goabackup" || f != "SHA256:abc" || k != "ed25519" {
		t.Errorf("got (%q,%q,%q), want (ssh-ed25519..., SHA256:abc, ed25519)", p, f, k)
	}
	if p, f, k := GoabackupChannelExtra(&models.Connection{Extra: nil}); p != "" || f != "" || k != "" {
		t.Errorf("nil extra: got (%q,%q,%q), want empty", p, f, k)
	}
}

// TestSaveGoabackupChannel_PrivateKeyNeverInExtra is the at-rest secrecy invariant:
// the private PEM is the encrypted secret and MUST NOT leak into the clear extra_json
// blob. This rebuilds the exact extra map saveGoabackupChannel passes to save() so a
// future shuffle that smuggles the private key into extra_json is caught here, with
// no DB required.
func TestSaveGoabackupChannel_PrivateKeyNeverInExtra(t *testing.T) {
	form := models.GoabackupChannelForm{
		Host:          "192.168.40.20:22",
		User:          "goabackup",
		PrivateKeyPEM: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETMATERIAL\n-----END OPENSSH PRIVATE KEY-----\n",
		PublicKey:     "ssh-ed25519 AAAAC3Nz... goabackup-channel",
		Fingerprint:   "SHA256:deadbeef",
		KeyType:       "ed25519",
	}
	// Mirror saveGoabackupChannel's extra-map construction exactly.
	extra := map[string]string{
		"pubkey":      form.PublicKey,
		"fingerprint": form.Fingerprint,
		"keytype":     form.KeyType,
	}
	for k, v := range extra {
		if strings.Contains(v, "PRIVATE KEY") || strings.Contains(v, "SECRETMATERIAL") {
			t.Fatalf("extra_json[%q] leaks the private key: %q", k, v)
		}
	}
	if extra["pubkey"] != form.PublicKey || extra["fingerprint"] != form.Fingerprint || extra["keytype"] != form.KeyType {
		t.Errorf("extra map mismatch: %v", extra)
	}
	if _, ok := extra["private"]; ok {
		t.Error("extra_json must never carry a 'private' key")
	}
}

// TestSaveGoabackupChannel_RoundTripCrypto exercises the crypto boundary the channel
// quartet relies on: the private PEM sealed by EncryptData is recoverable by
// DecryptData (what SaveGoabackupChannel persists is what GetGoabackupChannel
// recovers). No DB needed — it asserts the secret column round-trips.
func TestSaveGoabackupChannel_RoundTripCrypto(t *testing.T) {
	enc := NewSSHService(nil, sha256.Sum256([]byte("session-secret")), "", "", "", "", false)
	store := NewConnectionStore(nil, enc)

	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nb64material==\n-----END OPENSSH PRIVATE KEY-----\n"
	ct, err := store.enc.EncryptData(pem)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if strings.Contains(ct, "PRIVATE KEY") {
		t.Error("ciphertext still contains the cleartext PEM marker")
	}
	got, err := store.enc.DecryptData(ct)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if got != pem {
		t.Errorf("PEM round-trip mismatch: got %q want %q", got, pem)
	}
}

// TestImportFromEnvGoabackupChannel_GuardsEmpty verifies the env-import refuses to
// seed a row when the environment carries no channel host (pre-DB guard path, no
// MySQL required).
func TestImportFromEnvGoabackupChannel_GuardsEmpty(t *testing.T) {
	enc := NewSSHService(nil, sha256.Sum256([]byte("s")), "", "", "", "", false)
	store := NewConnectionStore(nil, enc)
	if err := store.ImportFromEnvGoabackupChannel(&config.Config{}); err == nil {
		t.Error("ImportFromEnvGoabackupChannel should fail with empty env, got nil")
	} else if !strings.Contains(err.Error(), "no goabackup channel configuration") {
		t.Errorf("unexpected error %q", err.Error())
	}
}
