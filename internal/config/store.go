package config

import "sync/atomic"

// ProxmoxConn is an immutable snapshot of the Proxmox connection parameters in
// effect at a point in time. It is swapped atomically as a whole (never mutated
// field by field) so a reader always observes a coherent set — e.g. it can never
// see a new URL paired with the old token. The zero value (all empty strings)
// represents an unconfigured Proxmox.
type ProxmoxConn struct {
	URL         string
	Node        string
	TokenID     string
	TokenSecret string
	Storage     string
	Bridge      string

	// Restore-test sandbox attributes (Jalon 2). They live ALONGSIDE Storage/Bridge
	// in the same immutable snapshot so a hot-reload swaps them atomically too.
	//
	// SandboxVlan is the isolation VLAN forced on every sandbox NIC before boot. It
	// is never 0 once resolved: SandboxVlanTag() floors a 0/empty value back to the
	// hard default (99). RestoreStorage overrides the storage a restore-test guest
	// is restored into (empty = fall through to pm.Storage, then auto-detect).
	// CryptRemote is the rclone remote the N1 off-site integrity check targets
	// (empty = the hard default "gcrypt"), passed to the helper's cryptcheck op so
	// it is no longer wired to a single PME's remote name.
	SandboxVlan    int
	RestoreStorage string
	CryptRemote    string

	// SandboxBridge is the bridge the sandbox NICs are forced onto, COUPLED to
	// SandboxVlan (the pair must carry the routed-nowhere isolation VLAN). It is
	// DELIBERATELY separate from Bridge (the VM/CT creation bridge): they must never
	// share a value, otherwise a creation bridge of vmbr0 (prod) would silently
	// become the sandbox bridge and a restored prod guest could boot onto a live
	// segment if vmbr0 does not trunk the isolation VLAN. SandboxBridgeName() floors
	// an empty value to the hard vmbr1 fallback — never to Bridge.
	SandboxBridge string
}

// sandboxVlanFallback is the hard, never-disableable isolation VLAN used when no
// VLAN is configured anywhere (0/empty at every layer). It mirrors the bash helper
// posture: a sandbox always lands on a routed-nowhere VLAN, never on VLAN 0/native.
const sandboxVlanFallback = 99

// cryptRemoteFallback is the hard default rclone remote for the N1 off-site
// integrity check when none is configured (DB extra_json / env both empty).
const cryptRemoteFallback = "gcrypt"

// sandboxBridgeFallback is the hard, never-disableable bridge used for sandbox NICs
// when no sandbox bridge is configured anywhere. It mirrors the bash helper / Jalon-1
// posture: the HomeLab isolation VLAN lives on vmbr1, so this is the literal of last
// resort — NEVER the creation bridge (which is often vmbr0 = prod and may not trunk
// the isolation VLAN).
const sandboxBridgeFallback = "vmbr1"

// SandboxVlanTag returns the isolation VLAN to force on sandbox guests, flooring a
// 0/negative/empty value back to the hard fallback (99). The isolation guarantee
// must never degrade to "no tag" / VLAN 0, so this method is the single place that
// resolves the effective tag for the restore engine.
func (c ProxmoxConn) SandboxVlanTag() int {
	if c.SandboxVlan <= 0 || c.SandboxVlan > 4094 {
		return sandboxVlanFallback
	}
	return c.SandboxVlan
}

// CryptCheckRemote returns the rclone remote for the N1 off-site integrity check,
// falling back to the hard default ("gcrypt") when none is configured.
func (c ProxmoxConn) CryptCheckRemote() string {
	if c.CryptRemote == "" {
		return cryptRemoteFallback
	}
	return c.CryptRemote
}

// SandboxBridgeName returns the bridge to force sandbox NICs onto, flooring an empty
// value to the hard vmbr1 fallback. It NEVER falls back to the creation bridge
// (c.Bridge): the sandbox bridge is a distinct, isolation-coupled attribute, so an
// admin who never set it gets the routed-nowhere vmbr1 rather than inheriting a
// possibly-prod creation bridge. This is the single place the restore engine resolves
// the effective sandbox bridge — the non-negotiable "don't degrade under vmbr1" rule.
func (c ProxmoxConn) SandboxBridgeName() string {
	if c.SandboxBridge == "" {
		return sandboxBridgeFallback
	}
	return c.SandboxBridge
}

// Configured reports whether this connection has the minimum fields to talk to
// the Proxmox API (URL + token id + token secret).
func (c ProxmoxConn) Configured() bool {
	return c.URL != "" && c.TokenID != "" && c.TokenSecret != ""
}

// SSHCredsSink is the narrow contract ConfigStore needs to push refreshed Proxmox
// credentials into the SSH service at reload time, without the config package
// importing services (which would create an import cycle). *services.SSHService
// satisfies it via SetProxmoxCreds.
type SSHCredsSink interface {
	SetProxmoxCreds(url, node, tokenID, secret string)
}

// ConfigStore is the single source of truth for the Proxmox connection that may
// change at runtime (in-app onboarding / hot-reload). The live connection is held
// in an atomic.Pointer[ProxmoxConn] so ALL concurrent readers — the cache and
// proxmox-auth workers, BackupService, restore_engine AND the request-goroutine
// handlers — read it lock-free via Snapshot() and a hot-reload (ApplyProxmox)
// publishes a brand-new value with a single atomic swap. There is no transitory
// window where fields are half-updated, and crucially no plain (unsynchronised)
// memory the handlers read concurrently with a write.
//
// ApplyProxmox deliberately does NOT mutate the cfg.Proxmox* mirror fields: those
// strings would otherwise be written here while handler goroutines read them with
// no synchronisation, which the Go memory model classifies as a data race. The
// atomic.Pointer is the only post-boot source of truth; cfg.Proxmox* is read once
// at construction to seed it and never written again.
type ConfigStore struct {
	cfg *Config
	ssh SSHCredsSink
	cur atomic.Pointer[ProxmoxConn]

	// env is the Proxmox connection derived from the environment at construction
	// time, frozen BEFORE any DB override is applied. It is the immutable fallback
	// restored by RollbackToEnv when the in-app DB row is deleted, so a rollback
	// reverts to env live (without a restart) and never accidentally re-applies a
	// since-overridden DB value mirrored into cfg.
	env ProxmoxConn
}

// NewConfigStore builds a ConfigStore seeded from the current cfg.Proxmox* values
// and wires the SSH credentials sink (may be nil in tests). The initial snapshot
// reflects whatever Load() put into cfg (env defaults) before any DB override.
// The same env-derived values are frozen as the rollback fallback.
//
// This is the ONLY place cfg.Proxmox* is read; the seed happens at boot, before any
// request/worker goroutine starts, so it is sequenced-before every later Snapshot
// read. cfg.Proxmox* is never written again, so no data race with handler reads.
func NewConfigStore(cfg *Config, ssh SSHCredsSink) *ConfigStore {
	env := ProxmoxConn{
		URL:         cfg.ProxmoxURL,
		Node:        cfg.ProxmoxNode,
		TokenID:     cfg.ProxmoxTokenID,
		TokenSecret: cfg.ProxmoxTokenSecret,
		Storage:     cfg.ProxmoxStorage,
		Bridge:      cfg.ProxmoxBridge,
		// Restore-test sandbox attributes seeded from the env layer (frozen at boot);
		// a DB row overrides them at ApplyProxmox time, same as Storage/Bridge.
		SandboxVlan:    cfg.SandboxVlan,
		RestoreStorage: cfg.RestoreStorage,
		// No dedicated CRYPT_REMOTE env yet — seed empty so CryptCheckRemote() floors
		// to the hard default; a DB row can still override it.
		CryptRemote: "",
		// Sandbox bridge seeded from its OWN env (GOABACKUP_SANDBOX_BRIDGE), never from
		// cfg.ProxmoxBridge — the isolation bridge must not inherit the creation bridge.
		// Empty floors to the hard vmbr1 fallback via SandboxBridgeName().
		SandboxBridge: cfg.SandboxBridge,
	}
	s := &ConfigStore{cfg: cfg, ssh: ssh, env: env}
	c := env
	s.cur.Store(&c)
	return s
}

// ProxmoxSnapshot returns the live Proxmox connection by value. It is lock-free
// and always coherent (a single atomic load of an immutable struct). Callers MUST
// re-read it at the top of each operation rather than caching it across a long
// run, so a hot-reload takes effect on the next iteration.
func (s *ConfigStore) ProxmoxSnapshot() ProxmoxConn {
	if p := s.cur.Load(); p != nil {
		return *p
	}
	return ProxmoxConn{}
}

// ProxmoxConfigured reports whether the live Proxmox connection is usable.
func (s *ConfigStore) ProxmoxConfigured() bool {
	return s.ProxmoxSnapshot().Configured()
}

// ApplyProxmox publishes a new Proxmox connection atomically (single swap) and
// pushes the fresh credentials into the SSH service so the root console targets the
// new Proxmox immediately. This is the ONLY write path for the Proxmox connection
// after boot; it is safe to call concurrently with any number of Snapshot readers.
//
// It deliberately does NOT touch the cfg.Proxmox* mirror fields. Handlers no longer
// read those concurrently — they go through ProxmoxSnapshot() — so mutating them
// here would be a data race against the construction-time seed read with no upside.
func (s *ConfigStore) ApplyProxmox(conn ProxmoxConn) {
	// Publish the immutable snapshot: concurrent Snapshot readers flip from the old
	// coherent value straight to the new coherent value, never a mix.
	c := conn
	s.cur.Store(&c)

	// Refresh the SSH service creds (console root) so it follows the new Proxmox.
	if s.ssh != nil {
		s.ssh.SetProxmoxCreds(conn.URL, conn.Node, conn.TokenID, conn.TokenSecret)
	}
}

// RollbackToEnv re-publishes the environment-derived connection frozen at
// construction. It is the live counterpart of deleting the in-app DB row: the
// configuration reverts to the env fallback (or to unconfigured when env carried
// no Proxmox) immediately, with the same atomic-swap + SSH-refresh guarantees as
// ApplyProxmox. It returns the restored connection so the caller can report the
// resulting source.
func (s *ConfigStore) RollbackToEnv() ProxmoxConn {
	s.ApplyProxmox(s.env)
	return s.env
}

// EnvProxmox returns the environment-derived Proxmox connection frozen at
// construction (read-only fallback), regardless of any DB override applied since.
func (s *ConfigStore) EnvProxmox() ProxmoxConn {
	return s.env
}
