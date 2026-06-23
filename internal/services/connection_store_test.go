package services

import (
	"crypto/sha256"
	"strings"
	"testing"

	"goacloud/internal/config"
	"goacloud/internal/models"
)

// TestProxmoxExtra verifies storage/bridge extraction from a connection's
// extra_json map, including the nil-safe fallbacks.
func TestProxmoxExtra(t *testing.T) {
	if s, b := ProxmoxExtra(nil); s != "" || b != "" {
		t.Errorf("nil connection: got (%q,%q), want empty", s, b)
	}
	c := &models.Connection{Extra: map[string]string{"storage": "local-lvm", "bridge": "vmbr1"}}
	if s, b := ProxmoxExtra(c); s != "local-lvm" || b != "vmbr1" {
		t.Errorf("got (%q,%q), want (local-lvm,vmbr1)", s, b)
	}
	c2 := &models.Connection{Extra: nil}
	if s, b := ProxmoxExtra(c2); s != "" || b != "" {
		t.Errorf("nil extra: got (%q,%q), want empty", s, b)
	}
}

// TestConnectionSecretCryptoRoundTrip exercises the exact crypto boundary the
// ConnectionStore relies on: the SSHService EncryptData/DecryptData the store uses
// to seal/open the Proxmox token secret. A DB is NOT required for this — it asserts
// that what SaveProxmox stores (ciphertext) is what GetProxmox can recover.
func TestConnectionSecretCryptoRoundTrip(t *testing.T) {
	enc := NewSSHService(nil, sha256.Sum256([]byte("session-secret")), "", "", "", "", false)
	store := NewConnectionStore(nil, enc)

	for _, secret := range []string{"", "pve-token-abc-123", "with spaces and =/+ symbols"} {
		ct, err := store.enc.EncryptData(secret)
		if err != nil {
			t.Fatalf("EncryptData(%q): %v", secret, err)
		}
		if ct == secret && secret != "" {
			t.Errorf("ciphertext equals plaintext for %q", secret)
		}
		got, err := store.enc.DecryptData(ct)
		if err != nil {
			t.Fatalf("DecryptData: %v", err)
		}
		if got != secret {
			t.Errorf("round-trip mismatch: got %q want %q", got, secret)
		}
	}
}

// TestImportFromEnv_GuardsEmpty verifies the env-import refuses to seed a DB row
// when the environment carries no Proxmox connection (the precondition that keeps
// a no-op click from writing a useless empty row). This exercises the guard path
// before any DB access, so no MySQL is required.
func TestImportFromEnv_GuardsEmpty(t *testing.T) {
	enc := NewSSHService(nil, sha256.Sum256([]byte("s")), "", "", "", "", false)
	store := NewConnectionStore(nil, enc)

	cases := []*config.Config{
		{},                             // nothing
		{ProxmoxURL: "https://x:8006"}, // URL but no token id
		{ProxmoxTokenID: "id@pve!t"},   // token id but no URL
	}
	for i, cfg := range cases {
		if err := store.ImportFromEnv(cfg); err == nil {
			t.Errorf("case %d: ImportFromEnv should fail with incomplete env, got nil", i)
		} else if !strings.Contains(err.Error(), "no Proxmox configuration") {
			t.Errorf("case %d: unexpected error %q", i, err.Error())
		}
	}
}

// TestConnectionSecretWrongKeyFails confirms a SESSION_SECRET change makes a stored
// secret undecipherable (the documented re-onboarding case GetProxmox handles
// without panicking).
func TestConnectionSecretWrongKeyFails(t *testing.T) {
	enc := NewSSHService(nil, sha256.Sum256([]byte("secret-A")), "", "", "", "", false)
	other := NewSSHService(nil, sha256.Sum256([]byte("secret-B")), "", "", "", "", false)
	ct, err := enc.EncryptData("pve-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.DecryptData(ct); err == nil {
		t.Error("decrypt with a different SESSION_SECRET-derived key must fail")
	}
}
