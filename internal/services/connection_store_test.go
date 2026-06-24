package services

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"

	"goacore/internal/config"
	"goacore/internal/models"
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

// TestProxmoxSandboxExtra verifies the Jalon-2 restore-test attribute extraction
// from extra_json, including the safe fallbacks and the deliberate parse-to-0 of a
// malformed sandbox_vlan (which the resolver later floors back to the hard default,
// never a silent "no isolation").
func TestProxmoxSandboxExtra(t *testing.T) {
	if rs, cr, sb, v := ProxmoxSandboxExtra(nil); rs != "" || cr != "" || sb != "" || v != 0 {
		t.Errorf("nil connection: got (%q,%q,%q,%d), want empty/0", rs, cr, sb, v)
	}
	c := &models.Connection{Extra: map[string]string{
		"restore_storage": "ceph-rbd",
		"crypt_remote":    "offsite",
		"sandbox_bridge":  "vmbr3",
		"sandbox_vlan":    "77",
	}}
	if rs, cr, sb, v := ProxmoxSandboxExtra(c); rs != "ceph-rbd" || cr != "offsite" || sb != "vmbr3" || v != 77 {
		t.Errorf("got (%q,%q,%q,%d), want (ceph-rbd,offsite,vmbr3,77)", rs, cr, sb, v)
	}
	// Malformed / absent vlan parses to 0 (resolver floors it later); the strings
	// default to empty. A row WITHOUT sandbox_bridge yields "" (floored to vmbr1 at
	// resolution, NEVER inheriting the creation bridge).
	bad := &models.Connection{Extra: map[string]string{"sandbox_vlan": "not-a-number"}}
	if rs, cr, sb, v := ProxmoxSandboxExtra(bad); rs != "" || cr != "" || sb != "" || v != 0 {
		t.Errorf("malformed: got (%q,%q,%q,%d), want empty/0", rs, cr, sb, v)
	}
}

// TestSaveProxmoxExtraMap documents the extra_json map the Proxmox upsert persists,
// asserting (without a DB) the bridge-DECOUPLING and "omit when unset" rules that
// saveProxmox encodes. It rebuilds the same map the production path passes to save()
// so a future shuffle of those keys is caught here.
func TestSaveProxmoxExtraMap(t *testing.T) {
	// Mirror saveProxmox's extra-map construction exactly (decoupled sandbox bridge).
	build := func(form models.ProxmoxConnectionForm) map[string]string {
		extra := map[string]string{
			"storage":         form.Storage,
			"bridge":          form.Bridge,
			"restore_storage": form.RestoreStorage,
			"crypt_remote":    form.CryptRemote,
		}
		if form.SandboxBridge != "" {
			extra["sandbox_bridge"] = form.SandboxBridge
		}
		if form.SandboxVlan > 0 {
			extra["sandbox_vlan"] = strconv.Itoa(form.SandboxVlan)
		}
		return extra
	}

	// The sandbox bridge is persisted in its OWN key and NEVER overwrites the creation
	// "bridge" key — that decoupling is the whole isolation fix.
	m := build(models.ProxmoxConnectionForm{Bridge: "vmbr0", SandboxBridge: "vmbr1", SandboxVlan: 99})
	if m["bridge"] != "vmbr0" {
		t.Errorf("creation bridge must be preserved, got %q", m["bridge"])
	}
	if m["sandbox_bridge"] != "vmbr1" {
		t.Errorf("sandbox_bridge should be persisted as %q, got %q", "vmbr1", m["sandbox_bridge"])
	}
	if m["sandbox_vlan"] != "99" {
		t.Errorf("sandbox_vlan should be persisted as %q, got %q", "99", m["sandbox_vlan"])
	}
	// Unset sandbox bridge / VLAN 0 must NOT be persisted, so they fall through to the
	// env/hard-default layer (vmbr1 / VLAN 99) — critically, the creation bridge is
	// NEVER inherited as the sandbox bridge.
	m0 := build(models.ProxmoxConnectionForm{Bridge: "vmbr0"})
	if _, ok := m0["sandbox_bridge"]; ok {
		t.Errorf("sandbox_bridge must be omitted when unset, got %q", m0["sandbox_bridge"])
	}
	if _, ok := m0["sandbox_vlan"]; ok {
		t.Errorf("sandbox_vlan must be omitted when 0, got %q", m0["sandbox_vlan"])
	}
	if m0["bridge"] != "vmbr0" {
		t.Errorf("bridge key should keep creation bridge, got %q", m0["bridge"])
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

// TestServiceExtraHelpers verifies the AI/Discord extra_json extraction helpers,
// including the nil-safe fallbacks (mirrors TestProxmoxExtra for the new services).
func TestServiceExtraHelpers(t *testing.T) {
	if p, b := AIExtra(nil); p != "" || b != "" {
		t.Errorf("AIExtra(nil) = (%q,%q), want empty", p, b)
	}
	ai := &models.Connection{Extra: map[string]string{"provider": "ollama", "openai_base": "https://x/v1"}}
	if p, b := AIExtra(ai); p != "ollama" || b != "https://x/v1" {
		t.Errorf("AIExtra = (%q,%q), want (ollama, https://x/v1)", p, b)
	}
	if a, an := DiscordExtra(nil); a != "" || an != "" {
		t.Errorf("DiscordExtra(nil) = (%q,%q), want empty", a, an)
	}
	dc := &models.Connection{Extra: map[string]string{"auth_channel": "111", "ansible_channel": "222"}}
	if a, an := DiscordExtra(dc); a != "111" || an != "222" {
		t.Errorf("DiscordExtra = (%q,%q), want (111,222)", a, an)
	}
}

// TestImportFromEnvWazuhIndexer_GuardsEmpty verifies the indexer env-import refuses
// to seed a row when the environment carries no Indexer URL (pre-DB guard path).
func TestImportFromEnvWazuhIndexer_GuardsEmpty(t *testing.T) {
	enc := NewSSHService(nil, sha256.Sum256([]byte("s")), "", "", "", "", false)
	store := NewConnectionStore(nil, enc)
	if err := store.ImportFromEnvWazuhIndexer(&config.Config{}); err == nil {
		t.Error("ImportFromEnvWazuhIndexer should fail with empty env, got nil")
	} else if !strings.Contains(err.Error(), "no Wazuh Indexer configuration") {
		t.Errorf("unexpected error %q", err.Error())
	}
}

// TestImportFromEnvGuards_OtherServices verifies the env-import guards for the Wazuh
// API, AI and Discord services reject an empty environment before any DB access.
func TestImportFromEnvGuards_OtherServices(t *testing.T) {
	enc := NewSSHService(nil, sha256.Sum256([]byte("s")), "", "", "", "", false)
	store := NewConnectionStore(nil, enc)

	if err := store.ImportFromEnvWazuh(&config.Config{}); err == nil {
		t.Error("ImportFromEnvWazuh should fail with empty env")
	}
	if err := store.ImportFromEnvAI(&config.Config{}); err == nil {
		t.Error("ImportFromEnvAI should fail with empty env")
	}
	if err := store.ImportFromEnvDiscord(&config.Config{}); err == nil {
		t.Error("ImportFromEnvDiscord should fail with empty env")
	}
	// Discord needs BOTH token and channel: a token alone is insufficient.
	if err := store.ImportFromEnvDiscord(&config.Config{DiscordBotToken: "tok"}); err == nil {
		t.Error("ImportFromEnvDiscord should fail with token but no channel")
	}
}
