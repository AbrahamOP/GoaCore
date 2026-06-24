package services

import (
	"context"
	"testing"
)

// stubAI is a trivial AIClient used to assert the registry stores/returns the exact
// interface value (and the holder{nil} vs nil-holder distinction).
type stubAI struct{ id string }

func (s stubAI) EnrichAlert(context.Context, AIAlertContext) (string, error) { return s.id, nil }

// TestRegistryAccessorsNilWhenEmpty: a fresh registry returns nil for every service.
func TestRegistryAccessorsNilWhenEmpty(t *testing.T) {
	r := NewServiceRegistry(false)
	if r.Wazuh() != nil {
		t.Error("Wazuh() should be nil on a fresh registry")
	}
	if r.Indexer() != nil {
		t.Error("Indexer() should be nil on a fresh registry")
	}
	if r.AI() != nil {
		t.Error("AI() should be nil on a fresh registry")
	}
	if r.Discord() != nil {
		t.Error("Discord() should be nil on a fresh registry")
	}
}

// TestRegistrySeedAndApplyIndexer: seeding then hot-reloading the Indexer publishes
// new clients via a single atomic swap, and an empty URL disables the service.
func TestRegistrySeedAndApplyIndexer(t *testing.T) {
	r := NewServiceRegistry(true)

	seed := NewWazuhIndexerClient("https://idx:9200", "u", "p", true)
	r.SeedIndexer(seed, "https://idx:9200", "u", "p")
	if got := r.Indexer(); got != seed {
		t.Fatal("Indexer() should return the seeded client")
	}

	r.ApplyIndexer("https://idx2:9200", "u2", "p2")
	got := r.Indexer()
	if got == nil || got == seed {
		t.Fatal("ApplyIndexer should publish a NEW client (atomic swap)")
	}
	if got.BaseURL != "https://idx2:9200" {
		t.Errorf("BaseURL = %q, want https://idx2:9200", got.BaseURL)
	}

	// Empty URL disables the service.
	r.ApplyIndexer("", "", "")
	if r.Indexer() != nil {
		t.Error("ApplyIndexer with empty URL should publish nil (disabled)")
	}
}

// TestRegistryApplyWazuh: hot-reloading the Wazuh API client swaps in a fresh client
// (empty JWT cache); empty URL disables.
func TestRegistryApplyWazuh(t *testing.T) {
	r := NewServiceRegistry(true)
	r.ApplyWazuh("https://wz:55000", "user", "pass")
	got := r.Wazuh()
	if got == nil || got.BaseURL != "https://wz:55000" {
		t.Fatalf("Wazuh() = %+v, want a client with the new base URL", got)
	}
	if got.User != "user" {
		t.Errorf("User = %q, want user", got.User)
	}
	r.ApplyWazuh("", "", "")
	if r.Wazuh() != nil {
		t.Error("ApplyWazuh with empty URL should disable (nil)")
	}
}

// TestRegistryAIHolderDistinction is the load-bearing nil-holder vs holder{nil} test:
//   - never seeded             => AI() nil,
//   - ApplyAI(openai,no key)   => holder{nil} => AI() nil (configured-but-disabled),
//   - ApplyAI(ollama,...)      => a usable client,
//   - ApplyAI(empty provider)  => nil holder => AI() nil (disabled).
func TestRegistryAIHolderDistinction(t *testing.T) {
	r := NewServiceRegistry(false)

	// Never seeded.
	if r.AI() != nil {
		t.Fatal("AI() should be nil before any seed/apply")
	}

	// Seed with a usable client.
	r.SeedAI(stubAI{id: "seed"}, "ollama", "http://o:11434", "", "m", "")
	if c, ok := r.AI().(stubAI); !ok || c.id != "seed" {
		t.Fatalf("AI() = %v, want seeded stub", r.AI())
	}

	// OpenAI without a key => NewAIClient returns nil => holder{nil} => AI() nil,
	// but the holder is non-nil (configured-but-disabled), distinct from never-seeded.
	r.ApplyAI("openai", "", "", "gpt", "")
	if r.AI() != nil {
		t.Error("AI() should be nil for openai-without-key (disabled)")
	}
	if r.ai.Load() == nil {
		t.Error("the holder should be non-nil (configured-but-disabled), not a nil holder")
	}

	// Ollama => a usable client.
	r.ApplyAI("ollama", "http://o:11434", "", "mistral", "")
	if r.AI() == nil {
		t.Error("AI() should be non-nil for an ollama provider")
	}

	// Empty provider => disabled (nil holder).
	r.ApplyAI("", "", "", "", "")
	if r.AI() != nil {
		t.Error("AI() should be nil for an empty provider (disabled)")
	}
	if r.ai.Load() != nil {
		t.Error("empty provider should store a nil holder (never-seeded equivalent)")
	}
}

// TestRegistryApplyAI_ProviderSwitch asserts a live ollama→openai switch publishes a
// usable OpenAI client (key present) via a single atomic swap — the Sub-lot C path
// that lets an operator change provider without a restart.
func TestRegistryApplyAI_ProviderSwitch(t *testing.T) {
	r := NewServiceRegistry(false)

	r.ApplyAI("ollama", "http://o:11434", "", "mistral", "")
	first := r.AI()
	if _, ok := first.(*OllamaClient); !ok {
		t.Fatalf("AI() = %T, want *OllamaClient after ollama apply", first)
	}

	r.ApplyAI("openai", "", "sk-key", "gpt-4", "https://api.openai.com/v1")
	second := r.AI()
	oc, ok := second.(*OpenAIClient)
	if !ok {
		t.Fatalf("AI() = %T, want *OpenAIClient after openai apply", second)
	}
	if oc.APIKey != "sk-key" || oc.Model != "gpt-4" {
		t.Errorf("OpenAI client = %+v, want key=sk-key model=gpt-4", oc)
	}
	if second == first {
		t.Error("provider switch must publish a NEW client (atomic swap)")
	}
}

// TestRegistryDiscordSeed: the Discord holder is seeded and read; SeedDiscord(nil)
// freezes only the env snapshot and must leave Discord() nil.
func TestRegistryDiscordSeed(t *testing.T) {
	r := NewServiceRegistry(false)
	if r.Discord() != nil {
		t.Fatal("Discord() should be nil before seed")
	}
	// SeedDiscord with a nil bot only freezes the env snapshot (no live session in a
	// unit test). It must leave Discord() nil.
	r.SeedDiscord(nil, "tok", "chan", "", "")
	if r.Discord() != nil {
		t.Error("SeedDiscord(nil,...) must not publish a bot")
	}
}

// TestApplyDiscordNoOp: when the requested token+channels match the LIVE bot exactly,
// ApplyDiscord must be a no-op — it must NOT rebuild/Open a session (which would hit the
// network) and must leave the SAME *DiscordBot pointer published. This exercises the
// rate-limit-protecting short-circuit without any network. We plant a fake live bot
// (no real session) directly in the holder; the no-op path never touches the session.
func TestApplyDiscordNoOp(t *testing.T) {
	r := NewServiceRegistry(false)
	live := &DiscordBot{token: "tok", channelID: "chan", authChannelID: "a", ansibleChannelID: "b"}
	r.discord.Store(live)

	if err := r.ApplyDiscord("tok", "chan", "a", "b"); err != nil {
		t.Fatalf("ApplyDiscord no-op returned %v, want nil", err)
	}
	if got := r.Discord(); got != live {
		t.Error("ApplyDiscord no-op must keep the SAME live bot (no rebuild/Open)")
	}
}

// TestApplyDiscordDisable: an empty token (or channel) disables Discord — the holder is
// swapped to nil and the old session is closed (bounded, async). No network is needed:
// the disable path never builds a new session. We plant a fake live bot whose Close is a
// no-op (nil session ⇒ Close short-circuits), so the bounded-close goroutine is safe.
func TestApplyDiscordDisable(t *testing.T) {
	r := NewServiceRegistry(false)
	r.discord.Store(&DiscordBot{token: "tok", channelID: "chan"}) // nil session ⇒ Close() is a no-op

	if err := r.ApplyDiscord("", "", "", ""); err != nil {
		t.Fatalf("ApplyDiscord disable returned %v, want nil", err)
	}
	if r.Discord() != nil {
		t.Error("ApplyDiscord with empty token must publish a nil bot (disabled)")
	}
}

// TestApplyDiscordChangeOpensSession: a changed token forces a rebuild, which calls
// NewDiscordBot → session.Open(). With a bogus token and no Discord reachability that
// Open fails, so ApplyDiscord MUST return an error AND leave the previous bot live (no
// notification gap on a bad reload). This asserts the swap-LAST / keep-old-on-failure
// contract without depending on a successful Gateway connection.
func TestApplyDiscordChangeOpensSession(t *testing.T) {
	r := NewServiceRegistry(false)
	live := &DiscordBot{token: "old", channelID: "chan"}
	r.discord.Store(live)

	err := r.ApplyDiscord("a-different-token", "chan", "", "")
	if err == nil {
		t.Skip("ApplyDiscord unexpectedly opened a Gateway session (network available?) — skipping the failure-path assertion")
	}
	// On failure the OLD bot must remain published.
	if got := r.Discord(); got != live {
		t.Error("ApplyDiscord must keep the OLD bot live when opening the new session fails")
	}
}
