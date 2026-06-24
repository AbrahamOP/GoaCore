package services

import (
	"testing"
)

// TestProxmoxChannel_ConfiguredAcceptsEitherKeySource verifies the migrated
// Configured() accepts BOTH the DB-first in-memory PEM and the env key FILE, and
// rejects the missing-host / missing-key cases.
func TestProxmoxChannel_ConfiguredAcceptsEitherKeySource(t *testing.T) {
	cases := []struct {
		name string
		c    *ProxmoxChannel
		want bool
	}{
		{"nil channel", nil, false},
		{"empty", &ProxmoxChannel{}, false},
		{"host only, no key", &ProxmoxChannel{host: "h:22"}, false},
		{"keyPEM only, no host", &ProxmoxChannel{keyPEM: []byte("x")}, false},
		{"keyFile only, no host", &ProxmoxChannel{keyFile: "/k"}, false},
		{"host + keyPEM (DB path)", &ProxmoxChannel{host: "h:22", keyPEM: []byte("x")}, true},
		{"host + keyFile (env path)", &ProxmoxChannel{host: "h:22", keyFile: "/k"}, true},
	}
	for _, tc := range cases {
		if got := tc.c.Configured(); got != tc.want {
			t.Errorf("%s: Configured() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestNewProxmoxChannelFromKey_NormalizesHostAndHoldsKeyInMemory verifies the DB-first
// constructor normalises a port-less host and carries the PEM in memory (never a file
// path), so run() takes the in-memory parse path.
func TestNewProxmoxChannelFromKey_NormalizesHostAndHoldsKeyInMemory(t *testing.T) {
	pem := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n")
	c := NewProxmoxChannelFromKey("192.168.40.20", "goabackup", pem)
	if c.host != "192.168.40.20:22" {
		t.Errorf("host = %q, want 192.168.40.20:22 (default port appended)", c.host)
	}
	if string(c.keyPEM) != string(pem) {
		t.Error("keyPEM not carried in memory")
	}
	if c.keyFile != "" {
		t.Errorf("keyFile = %q, want empty (DB path never uses a file)", c.keyFile)
	}
	if !c.Configured() {
		t.Error("a host + in-memory PEM channel must report Configured()")
	}
}

// TestChannelRegistry_HotReloadAndRollback exercises the registry's atomic lifecycle:
// seed env → provision (ApplyChannel) → rollback. It is the channel analogue of the
// ServiceRegistry seed/apply tests.
func TestChannelRegistry_HotReloadAndRollback(t *testing.T) {
	// Env-derived (key FILE) channel frozen as the rollback fallback.
	envCh := NewProxmoxChannel(nil) // unconfigured env
	envCh = &ProxmoxChannel{host: "envhost:22", keyFile: "/etc/goabackup.key"}
	reg := NewChannelRegistry(envCh)

	// Boot: the live channel is the env one.
	if got := reg.Channel(); got != envCh {
		t.Fatal("fresh registry must return the seeded env channel")
	}
	if reg.EnvChannel() != envCh {
		t.Error("EnvChannel() must return the frozen env fallback")
	}

	// Provision: a fresh in-app key (in-memory PEM) hot-reloads the live channel via a
	// single swap; the env fallback is untouched.
	k, err := GenerateEd25519Key("goabackup-channel")
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	reg.ApplyChannel("10.0.0.1:22", "goabackup", []byte(k.PrivateKey))
	live := reg.Channel()
	if live == envCh {
		t.Fatal("ApplyChannel must publish a NEW channel, not the env one")
	}
	if live.host != "10.0.0.1:22" || len(live.keyPEM) == 0 || live.keyFile != "" {
		t.Errorf("live channel after provision is wrong: host=%q keyPEM=%d keyFile=%q",
			live.host, len(live.keyPEM), live.keyFile)
	}
	if reg.EnvChannel() != envCh {
		t.Error("ApplyChannel must NOT mutate the frozen env fallback")
	}

	// Rollback (delete-without-env-key would publish env): live reverts to the env one.
	restored := reg.RollbackToEnv()
	if restored != envCh || reg.Channel() != envCh {
		t.Error("RollbackToEnv must republish the frozen env channel")
	}
}

// TestNewChannelRegistry_NilEnvNeverReturnsNilChannel verifies the registry never
// hands a nil channel even when seeded with nil: Channel() returns a real (unconfigured)
// channel so every caller can safely call Configured()/ops.
func TestNewChannelRegistry_NilEnvNeverReturnsNilChannel(t *testing.T) {
	reg := NewChannelRegistry(nil)
	if reg.Channel() == nil {
		t.Fatal("Channel() must never return nil")
	}
	if reg.Channel().Configured() {
		t.Error("a nil-seeded registry channel must be unconfigured")
	}
	// ApplyChannelClient(nil) also degrades to an unconfigured channel, never nil.
	reg.ApplyChannelClient(nil)
	if reg.Channel() == nil || reg.Channel().Configured() {
		t.Error("ApplyChannelClient(nil) must publish a non-nil, unconfigured channel")
	}
}

// chanProviderStub adapts a fixed channel to ChannelProvider for the BackupService
// wiring test (it is the test double for the registry).
type chanProviderStub struct{ c *ProxmoxChannel }

func (p chanProviderStub) Channel() *ProxmoxChannel { return p.c }

// TestBackupService_LiveChannelResolution verifies liveChannel() resolves through the
// provider (hot-reload aware) and never returns nil, including the unset-provider and
// provider-returns-nil cases.
func TestBackupService_LiveChannelResolution(t *testing.T) {
	s := newTestBackupService()

	// No provider wired → liveChannel() is a non-nil, unconfigured channel.
	if got := s.liveChannel(); got == nil || got.Configured() {
		t.Error("unset provider: liveChannel() must be non-nil and unconfigured")
	}

	// Provider returning nil → still non-nil, unconfigured.
	s.SetChannelProvider(chanProviderStub{c: nil})
	if got := s.liveChannel(); got == nil || got.Configured() {
		t.Error("nil-returning provider: liveChannel() must be non-nil and unconfigured")
	}

	// A configured channel flows through.
	ch := &ProxmoxChannel{host: "h:22", keyPEM: []byte("x")}
	s.SetChannelProvider(chanProviderStub{c: ch})
	if got := s.liveChannel(); got != ch {
		t.Error("liveChannel() must return the provider's channel")
	}

	// SetChannel shim wraps a frozen pointer in a static provider.
	s.SetChannel(ch)
	if got := s.liveChannel(); got != ch {
		t.Error("SetChannel shim must make liveChannel() return the frozen channel")
	}
}
