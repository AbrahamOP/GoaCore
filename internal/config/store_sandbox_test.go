package config

import "testing"

// TestSandboxVlanTag_FloorsToHardDefault asserts the isolation VLAN never degrades
// to 0/native: any 0/negative/out-of-range value resolves to the hard fallback 99,
// while a valid in-range value passes through unchanged.
func TestSandboxVlanTag_FloorsToHardDefault(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, 99},       // unset → hard default
		{-5, 99},      // negative → hard default
		{4095, 99},    // out of range high → hard default
		{99, 99},      // explicit default
		{99 + 1, 100}, // arbitrary valid
		{1, 1},        // lower bound
		{4094, 4094},  // upper bound
	}
	for _, tc := range cases {
		got := ProxmoxConn{SandboxVlan: tc.in}.SandboxVlanTag()
		if got != tc.want {
			t.Errorf("SandboxVlanTag(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestCryptCheckRemote_FallsBackToDefault asserts the N1 off-site remote falls back
// to the hard default ("gcrypt") only when unset, and otherwise passes through.
func TestCryptCheckRemote_FallsBackToDefault(t *testing.T) {
	if got := (ProxmoxConn{}).CryptCheckRemote(); got != "gcrypt" {
		t.Errorf("empty CryptRemote = %q, want gcrypt", got)
	}
	if got := (ProxmoxConn{CryptRemote: "offsite"}).CryptCheckRemote(); got != "offsite" {
		t.Errorf("CryptRemote override = %q, want offsite", got)
	}
}

// TestSandboxBridgeName_NeverInheritsCreationBridge is the core isolation invariant:
// the sandbox bridge floors an empty value to the hard vmbr1 fallback and NEVER to
// the creation bridge, so a prod creation bridge can never silently become the
// isolation bridge.
func TestSandboxBridgeName_NeverInheritsCreationBridge(t *testing.T) {
	// Empty sandbox bridge → hard vmbr1, regardless of the (prod) creation bridge.
	if got := (ProxmoxConn{Bridge: "vmbr0"}).SandboxBridgeName(); got != "vmbr1" {
		t.Errorf("empty SandboxBridge with creation bridge vmbr0 = %q, want vmbr1 (never inherit vmbr0)", got)
	}
	if got := (ProxmoxConn{}).SandboxBridgeName(); got != "vmbr1" {
		t.Errorf("empty SandboxBridge = %q, want vmbr1", got)
	}
	// An explicit sandbox bridge passes through unchanged, even alongside a creation bridge.
	if got := (ProxmoxConn{Bridge: "vmbr0", SandboxBridge: "vmbr9"}).SandboxBridgeName(); got != "vmbr9" {
		t.Errorf("explicit SandboxBridge = %q, want vmbr9", got)
	}
}

// TestNewConfigStore_SeedsSandboxAttributes verifies the env layer of the resolution
// order: ProxmoxConn snapshots carry the SandboxVlan / RestoreStorage seeded from
// cfg, and survive an ApplyProxmox swap that itself carries DB-layer overrides.
func TestNewConfigStore_SeedsSandboxAttributes(t *testing.T) {
	cfg := &Config{
		ProxmoxURL:     "https://env:8006",
		ProxmoxTokenID: "id@pve!t",
		ProxmoxBridge:  "vmbr0", // creation bridge — must NOT leak into the sandbox bridge
		// env-seeded sandbox attributes
		SandboxVlan:    77,
		RestoreStorage: "env-zfs",
		SandboxBridge:  "vmbr7", // dedicated sandbox bridge env
	}
	s := NewConfigStore(cfg, nil)

	got := s.ProxmoxSnapshot()
	if got.SandboxVlan != 77 || got.RestoreStorage != "env-zfs" {
		t.Fatalf("env seed not reflected: vlan=%d restore=%q", got.SandboxVlan, got.RestoreStorage)
	}
	// The dedicated sandbox bridge is seeded from its OWN env, decoupled from the
	// creation bridge (vmbr0).
	if got.SandboxBridge != "vmbr7" || got.SandboxBridgeName() != "vmbr7" {
		t.Errorf("sandbox bridge env seed = %q (resolved %q), want vmbr7", got.SandboxBridge, got.SandboxBridgeName())
	}
	if got.Bridge != "vmbr0" {
		t.Errorf("creation bridge = %q, want vmbr0 (independent of sandbox bridge)", got.Bridge)
	}
	if got.SandboxVlanTag() != 77 {
		t.Errorf("resolved vlan = %d, want 77", got.SandboxVlanTag())
	}
	// CryptRemote has no env seed yet → floors to the hard default.
	if got.CryptCheckRemote() != "gcrypt" {
		t.Errorf("crypt remote = %q, want gcrypt", got.CryptCheckRemote())
	}

	// A DB override (onboarding Save / boot reload) swaps the whole snapshot, sandbox
	// attributes included.
	s.ApplyProxmox(ProxmoxConn{
		URL: "https://db:8006", TokenID: "db@pve!t", TokenSecret: "x",
		SandboxVlan: 42, RestoreStorage: "db-ceph", CryptRemote: "offsite",
	})
	got = s.ProxmoxSnapshot()
	if got.SandboxVlanTag() != 42 || got.RestoreStorage != "db-ceph" || got.CryptCheckRemote() != "offsite" {
		t.Fatalf("DB override not live: %+v", got)
	}
	// The frozen env fallback keeps its sandbox attributes for rollback.
	if env := s.EnvProxmox(); env.SandboxVlan != 77 || env.RestoreStorage != "env-zfs" {
		t.Fatalf("env fallback clobbered: %+v", env)
	}
}
