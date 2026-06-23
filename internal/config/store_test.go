package config

import (
	"sync"
	"sync/atomic"
	"testing"
)

// fakeSink records the last Proxmox creds pushed by ConfigStore.ApplyProxmox and
// counts the calls, so tests can assert the SSH refresh fires on reload.
type fakeSink struct {
	mu                         sync.Mutex
	calls                      int
	url, node, tokenID, secret string
}

func (f *fakeSink) SetProxmoxCreds(url, node, tokenID, secret string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.url, f.node, f.tokenID, f.secret = url, node, tokenID, secret
}

func (f *fakeSink) snapshot() (int, string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.url, f.secret
}

func TestConfigStore_InitialSnapshotFromConfig(t *testing.T) {
	cfg := &Config{
		ProxmoxURL:         "https://env:8006",
		ProxmoxNode:        "pve",
		ProxmoxTokenID:     "id@pve!tok",
		ProxmoxTokenSecret: "envsecret",
		ProxmoxStorage:     "local",
		ProxmoxBridge:      "vmbr0",
	}
	s := NewConfigStore(cfg, nil)
	got := s.ProxmoxSnapshot()
	if got.URL != "https://env:8006" || got.TokenID != "id@pve!tok" || got.TokenSecret != "envsecret" {
		t.Fatalf("snapshot did not reflect cfg: %+v", got)
	}
	if !s.ProxmoxConfigured() {
		t.Error("expected configured with URL+TokenID+TokenSecret set")
	}
}

func TestConfigStore_ApplyProxmoxSwapsAndRefreshesSSH(t *testing.T) {
	// The cfg mirror is read once at construction to seed the env fallback; it must
	// NOT be written by ApplyProxmox (that plain write would race the handler reads,
	// which is exactly the bug this lot removed). Pre-load distinctive env values so
	// we can assert they survive the swap untouched.
	cfg := &Config{
		ProxmoxURL:         "https://env:8006",
		ProxmoxNode:        "envnode",
		ProxmoxTokenID:     "a",
		ProxmoxTokenSecret: "b",
		ProxmoxStorage:     "env-lvm",
		ProxmoxBridge:      "vmbr0",
	}
	sink := &fakeSink{}
	s := NewConfigStore(cfg, sink)

	s.ApplyProxmox(ProxmoxConn{
		URL:         "https://db:8006",
		Node:        "node2",
		TokenID:     "newid",
		TokenSecret: "newsecret",
		Storage:     "local-lvm",
		Bridge:      "vmbr1",
	})

	// Live snapshot reflects the new value.
	got := s.ProxmoxSnapshot()
	if got.URL != "https://db:8006" || got.TokenID != "newid" || got.TokenSecret != "newsecret" ||
		got.Storage != "local-lvm" || got.Bridge != "vmbr1" {
		t.Fatalf("snapshot not updated after ApplyProxmox: %+v", got)
	}
	// The cfg mirror is deliberately left untouched (single source of truth = the
	// atomic.Pointer). A write here would be a data race against concurrent handlers.
	if cfg.ProxmoxURL != "https://env:8006" || cfg.ProxmoxTokenSecret != "b" ||
		cfg.ProxmoxStorage != "env-lvm" || cfg.ProxmoxBridge != "vmbr0" {
		t.Errorf("cfg mirror must NOT be mutated by ApplyProxmox: %+v", cfg)
	}
	// SSH sink received the refreshed creds exactly once.
	calls, url, secret := sink.snapshot()
	if calls != 1 || url != "https://db:8006" || secret != "newsecret" {
		t.Errorf("SSH sink not refreshed correctly: calls=%d url=%q secret=%q", calls, url, secret)
	}
}

// TestConfigStore_DBOverrideThenRollback walks the full precedence lifecycle the
// boot + onboarding implement: env seed → DB override (onboarding Save / boot
// reload) → rollback (DELETE row). It asserts DB wins live, the SSH sink follows
// every transition, and RollbackToEnv restores EXACTLY the frozen env value (never
// a since-overridden mirror).
func TestConfigStore_DBOverrideThenRollback(t *testing.T) {
	cfg := &Config{
		ProxmoxURL:         "https://env:8006",
		ProxmoxNode:        "envnode",
		ProxmoxTokenID:     "env@pve!t",
		ProxmoxTokenSecret: "envsecret",
		ProxmoxStorage:     "env-lvm",
		ProxmoxBridge:      "vmbr0",
	}
	sink := &fakeSink{}
	s := NewConfigStore(cfg, sink)

	// Start: env is the live source (boot fallback when no DB row).
	if got := s.ProxmoxSnapshot(); got.URL != "https://env:8006" || got.TokenSecret != "envsecret" {
		t.Fatalf("initial snapshot should be env: %+v", got)
	}
	if got := s.EnvProxmox(); got.URL != "https://env:8006" || got.TokenSecret != "envsecret" {
		t.Fatalf("frozen env snapshot wrong: %+v", got)
	}

	// DB override (a DB row exists and is enabled → DB wins over env).
	s.ApplyProxmox(ProxmoxConn{
		URL: "https://db:8006", Node: "dbnode", TokenID: "db@pve!t",
		TokenSecret: "dbsecret", Storage: "db-lvm", Bridge: "vmbr1",
	})
	if got := s.ProxmoxSnapshot(); got.URL != "https://db:8006" || got.TokenSecret != "dbsecret" {
		t.Fatalf("DB override not live: %+v", got)
	}
	// The frozen env fallback must be UNCHANGED by the override.
	if got := s.EnvProxmox(); got.URL != "https://env:8006" || got.TokenSecret != "envsecret" {
		t.Fatalf("env fallback was clobbered by DB override: %+v", got)
	}
	// The cfg mirror is never mutated post-boot (the atomic.Pointer is the sole
	// source of truth); it must still carry the construction-time env values.
	if cfg.ProxmoxURL != "https://env:8006" || cfg.ProxmoxTokenSecret != "envsecret" {
		t.Fatalf("cfg mirror must stay at the seed value, got %q", cfg.ProxmoxURL)
	}

	// Rollback (DELETE row) → revert live to the frozen env fallback.
	restored := s.RollbackToEnv()
	if restored.URL != "https://env:8006" || restored.TokenSecret != "envsecret" {
		t.Fatalf("RollbackToEnv returned wrong conn: %+v", restored)
	}
	if got := s.ProxmoxSnapshot(); got.URL != "https://env:8006" || got.TokenSecret != "envsecret" {
		t.Fatalf("rollback did not restore env live: %+v", got)
	}
	// The mirror was never touched, so it is still the env value (unchanged).
	if cfg.ProxmoxURL != "https://env:8006" || cfg.ProxmoxTokenSecret != "envsecret" {
		t.Fatalf("cfg mirror should remain the seed env value: %+v", cfg)
	}

	// SSH sink followed every transition (init build does not push; 2 swaps do).
	calls, url, secret := sink.snapshot()
	if calls != 2 {
		t.Errorf("SSH sink expected 2 refreshes (override + rollback), got %d", calls)
	}
	if url != "https://env:8006" || secret != "envsecret" {
		t.Errorf("SSH sink last creds should be env after rollback: url=%q secret=%q", url, secret)
	}
}

// TestConfigStore_RollbackFromScratch covers the no-env case: a from-scratch
// instance (0 env, configured in-app) that rolls back becomes UNCONFIGURED, so the
// onboarding gate re-engages.
func TestConfigStore_RollbackFromScratch(t *testing.T) {
	s := NewConfigStore(&Config{}, &fakeSink{}) // no env Proxmox
	if s.ProxmoxConfigured() {
		t.Fatal("fresh instance with no env must be unconfigured")
	}
	// Admin onboards in-app.
	s.ApplyProxmox(ProxmoxConn{URL: "https://db:8006", TokenID: "db@pve!t", TokenSecret: "s"})
	if !s.ProxmoxConfigured() {
		t.Fatal("should be configured after in-app onboarding")
	}
	// Rollback with no env fallback → back to unconfigured.
	restored := s.RollbackToEnv()
	if restored.Configured() {
		t.Errorf("rollback with no env should yield unconfigured conn: %+v", restored)
	}
	if s.ProxmoxConfigured() {
		t.Error("instance must be unconfigured again after rollback with no env")
	}
}

func TestConfigStore_Unconfigured(t *testing.T) {
	s := NewConfigStore(&Config{}, nil)
	if s.ProxmoxConfigured() {
		t.Error("empty config must be unconfigured")
	}
	// URL only is not enough.
	s.ApplyProxmox(ProxmoxConn{URL: "https://x:8006"})
	if s.ProxmoxConfigured() {
		t.Error("URL without token must be unconfigured")
	}
}

// TestConfigStore_ConcurrentApplyAndSnapshot stresses the atomic.Pointer swap:
// many readers loop on ProxmoxSnapshot while writers swap whole connections. Each
// published connection has internally-consistent fields (URL/TokenID/TokenSecret
// all carry the same generation id), so a reader must NEVER observe a torn mix of
// two generations. Run with `go test` (no -race available here); the atomic.Pointer
// guarantees coherence by construction, and this asserts it at the value level.
func TestConfigStore_ConcurrentApplyAndSnapshot(t *testing.T) {
	s := NewConfigStore(&Config{}, nil)

	var stop atomic.Bool
	var wg sync.WaitGroup

	// Writers: publish coherent generations.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			gen := base
			for !stop.Load() {
				tag := genTag(gen)
				s.ApplyProxmox(ProxmoxConn{
					URL:         "https://host-" + tag,
					Node:        "node-" + tag,
					TokenID:     "tok-" + tag,
					TokenSecret: "sec-" + tag,
				})
				gen += 4
			}
		}(w)
	}

	// Readers: assert each snapshot is internally coherent.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200000; i++ {
				c := s.ProxmoxSnapshot()
				// Empty (initial) snapshot is fine before the first write.
				if c.URL == "" {
					continue
				}
				tag := c.URL[len("https://host-"):]
				if c.Node != "node-"+tag || c.TokenID != "tok-"+tag || c.TokenSecret != "sec-"+tag {
					t.Errorf("torn snapshot: %+v", c)
					return
				}
			}
		}()
	}

	// Let the readers run, then stop writers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Spin briefly to give readers time without sleeping (sleep is blocked).
		for i := 0; i < 5; i++ {
			s.ProxmoxSnapshot()
		}
		stop.Store(true)
	}()

	wg.Wait()
}

// TestConfigStore_ApplyDoesNotTouchMirror is the value-level guard for the data
// race fixed in this lot: ApplyProxmox must never write the cfg.Proxmox* mirror,
// because handlers read those strings on their own goroutines with no
// synchronisation. We hammer ApplyProxmox concurrently and assert the mirror keeps
// its construction-time value byte-for-byte (with -race this would also flag the
// write/read pair; without it, this asserts the invariant directly).
func TestConfigStore_ApplyDoesNotTouchMirror(t *testing.T) {
	cfg := &Config{
		ProxmoxURL:         "https://env:8006",
		ProxmoxNode:        "envnode",
		ProxmoxTokenID:     "env@pve!t",
		ProxmoxTokenSecret: "envsecret",
		ProxmoxStorage:     "env-lvm",
		ProxmoxBridge:      "vmbr0",
	}
	s := NewConfigStore(cfg, nil)

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				s.ApplyProxmox(ProxmoxConn{
					URL: "https://db:8006", Node: "dbnode", TokenID: "db@pve!t",
					TokenSecret: "dbsecret", Storage: "db-lvm", Bridge: "vmbr1",
				})
			}
		}()
	}
	wg.Wait()

	if cfg.ProxmoxURL != "https://env:8006" || cfg.ProxmoxNode != "envnode" ||
		cfg.ProxmoxTokenID != "env@pve!t" || cfg.ProxmoxTokenSecret != "envsecret" ||
		cfg.ProxmoxStorage != "env-lvm" || cfg.ProxmoxBridge != "vmbr0" {
		t.Fatalf("ApplyProxmox mutated the cfg mirror (data-race source): %+v", cfg)
	}
	// And the live snapshot is the applied value.
	if got := s.ProxmoxSnapshot(); got.URL != "https://db:8006" || got.TokenSecret != "dbsecret" {
		t.Fatalf("live snapshot wrong after concurrent apply: %+v", got)
	}
}

func genTag(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}
