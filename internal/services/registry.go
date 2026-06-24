package services

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ServiceRegistry is the client-snapshot counterpart of config.ConfigStore: it
// holds the LIVE service clients (Wazuh API, Wazuh Indexer, AI enrichment, Discord
// bot) and lets them be hot-reloaded in place after boot — without a restart and
// without a data race — exactly the way ConfigStore hot-reloads the Proxmox
// connection.
//
// Each stateless client lives behind an atomic.Pointer so every reader (request
// handlers AND background workers) reads it lock-free via the accessors below, and
// a single atomic Store publishes a new client. Readers MUST re-read the accessor
// at the top of each operation (per request / per worker tick) so a hot-reload
// takes effect on the next iteration — never cache the returned pointer across a
// long-running loop.
//
// Discord is the one stateful client (a live websocket): it is held behind the same
// atomic.Pointer but its writer (ApplyDiscord) serialises through discordMu and does
// REST-validate → Open-new → swap → bounded-close-old, with a no-op short-circuit when
// nothing changed. Every consumer reads it via Discord() AT EMIT TIME (through the
// DiscordProvider interface) so a swap reaches them with no frozen pointer left behind.
//
// For each service an immutable env snapshot is frozen at boot (the constructor
// args used to build the env-derived client) so a future RollbackToEnv can rebuild
// the env client live when the in-app DB row is deleted, mirroring
// config.ConfigStore.env.
type ServiceRegistry struct {
	wazuh   atomic.Pointer[WazuhClient]
	indexer atomic.Pointer[WazuhIndexerClient]
	ai      atomic.Pointer[aiHolder]
	discord atomic.Pointer[DiscordBot]

	// discordMu serialises Discord hot-reloads (swap-then-close). Concurrent saves
	// must not Open two Gateway sessions at once; the atomic.Pointer alone does not
	// prevent that race, so every ApplyDiscord runs under this mutex.
	discordMu sync.Mutex

	// Frozen-at-boot env snapshots per service, used by the (future) RollbackToEnv
	// to rebuild the env-derived client live when the DB row is deleted. They never
	// change after construction.
	envWazuh   wazuhEnv
	envIndexer wazuhEnv
	envAI      aiEnv
	envDiscord discordEnv

	// skipTLS is the boot TLS-verification policy, reused to rebuild Wazuh/Indexer
	// clients on Apply* (the onboarding form does not re-ask it).
	skipTLS bool
}

// aiHolder wraps the AIClient interface so it can be stored in an atomic.Pointer.
// The distinction is load-bearing:
//   - a nil *aiHolder            => "never seeded" (boot didn't build an AI client),
//   - &aiHolder{c: nil}          => "configured but disabled" (e.g. provider=openai
//     with no key: NewAIClient returns nil), and
//   - &aiHolder{c: someClient}   => a usable client.
//
// AI() collapses the first two to a nil AIClient for callers, which all nil-guard.
type aiHolder struct {
	c AIClient
}

// wazuhEnv is the frozen constructor input for a Wazuh / Indexer client.
type wazuhEnv struct {
	url, user, pass string
}

// aiEnv is the frozen constructor input for the AI client.
type aiEnv struct {
	provider, url, apiKey, model, openaiBase string
}

// discordEnv is the frozen constructor input for the Discord bot.
type discordEnv struct {
	token, channelID, authChannel, ansibleChannel string
}

// DiscordProvider is the narrow contract consumers depend on to read the LIVE
// Discord bot at emit time (never a frozen pointer captured at start). *ServiceRegistry
// satisfies it via Discord(). It exists so BackupService / restore_engine stay
// decoupled from the full registry. (The consumer migration to this interface is a
// later sub-lot; the contract is defined here.)
type DiscordProvider interface {
	Discord() *DiscordBot
}

// NewServiceRegistry builds an empty registry carrying the boot TLS policy. The
// holders are seeded via Seed* before any worker starts.
func NewServiceRegistry(skipTLS bool) *ServiceRegistry {
	return &ServiceRegistry{skipTLS: skipTLS}
}

// --- Accessors (lock-free; any may return nil — all consumers nil-guard) ---

// Wazuh returns the live Wazuh Manager API client, or nil when unconfigured.
func (r *ServiceRegistry) Wazuh() *WazuhClient {
	return r.wazuh.Load()
}

// Indexer returns the live Wazuh Indexer client, or nil when unconfigured.
func (r *ServiceRegistry) Indexer() *WazuhIndexerClient {
	return r.indexer.Load()
}

// AI returns the live AI enrichment client, or nil when unconfigured/disabled.
func (r *ServiceRegistry) AI() AIClient {
	if h := r.ai.Load(); h != nil {
		return h.c
	}
	return nil
}

// Discord returns the live Discord bot, or nil when unconfigured. Consumers MUST
// call this at emit time so a hot-reload swap reaches them.
func (r *ServiceRegistry) Discord() *DiscordBot {
	return r.discord.Load()
}

// --- Seed* (boot only, before workers start) ---

// SeedWazuh deposits the env-built Wazuh client (may be nil) and freezes its env
// snapshot for rollback. url/user/pass are the env constructor args.
func (r *ServiceRegistry) SeedWazuh(c *WazuhClient, url, user, pass string) {
	r.envWazuh = wazuhEnv{url: url, user: user, pass: pass}
	if c != nil {
		r.wazuh.Store(c)
	}
}

// SeedIndexer deposits the env-built Wazuh Indexer client (may be nil) and freezes
// its env snapshot for rollback.
func (r *ServiceRegistry) SeedIndexer(c *WazuhIndexerClient, url, user, pass string) {
	r.envIndexer = wazuhEnv{url: url, user: user, pass: pass}
	if c != nil {
		r.indexer.Store(c)
	}
}

// SeedAI deposits the env-built AI client (may be nil) and freezes its env snapshot.
// A nil client is still stored as &aiHolder{nil} ONLY when the env intended an AI
// provider; the caller passes the constructor args so a rollback can rebuild it.
func (r *ServiceRegistry) SeedAI(c AIClient, provider, url, apiKey, model, openaiBase string) {
	r.envAI = aiEnv{provider: provider, url: url, apiKey: apiKey, model: model, openaiBase: openaiBase}
	if c != nil {
		r.ai.Store(&aiHolder{c: c})
	}
}

// SeedDiscord deposits the env-built Discord bot (may be nil) and freezes its env
// snapshot. token/channel are the env constructor args (kept for rollback).
func (r *ServiceRegistry) SeedDiscord(b *DiscordBot, token, channelID, authChannel, ansibleChannel string) {
	r.envDiscord = discordEnv{token: token, channelID: channelID, authChannel: authChannel, ansibleChannel: ansibleChannel}
	if b != nil {
		r.discord.Store(b)
	}
}

// --- Apply* (post-boot hot-reload for the 3 stateless services) ---

// ApplyIndexer hot-reloads the Wazuh Indexer client: it builds a fresh client from
// the new credentials and publishes it with a single atomic swap. The Indexer client
// is stateless (Basic auth per request, no token cache, no socket) so the old client
// is simply GC'd — no Close, no cleanup. Empty url/user disables the service
// (publishes nil), so the Wazuh page and workers see "unconfigured" cleanly.
//
// It is safe to call concurrently with any number of Indexer() readers.
func (r *ServiceRegistry) ApplyIndexer(url, user, pass string) {
	if url == "" {
		r.indexer.Store(nil)
		return
	}
	r.indexer.Store(NewWazuhIndexerClient(url, user, pass, r.skipTLS))
}

// ApplyWazuh hot-reloads the Wazuh Manager API client. The new client starts with an
// empty JWT cache and lazily (re-)authenticates on its first call; the old client
// (an *http.Client holding a stale JWT) is GC'd, no Close needed. Empty url/user
// disables the service.
func (r *ServiceRegistry) ApplyWazuh(url, user, pass string) {
	if url == "" {
		r.wazuh.Store(nil)
		return
	}
	r.wazuh.Store(NewWazuhClient(url, user, pass, r.skipTLS))
}

// ApplyAI hot-reloads the AI enrichment client. It rebuilds via NewAIClient, which
// may return nil (e.g. provider=openai with no key); the nil is stored as
// &aiHolder{nil} so AI() reports "disabled" rather than "never seeded", and SOAR
// enrichment cleanly degrades (alert ships un-enriched). An empty provider disables
// the service (publishes a nil holder).
func (r *ServiceRegistry) ApplyAI(provider, url, apiKey, model, openaiBase string) {
	if provider == "" {
		r.ai.Store(nil)
		return
	}
	c := NewAIClient(provider, url, apiKey, model, openaiBase)
	r.ai.Store(&aiHolder{c: c})
}

// discordCloseTimeout bounds how long the goroutine that closes a replaced Discord
// session may run. discordgo's Close() can hang on a wedged websocket; this guard
// makes the close fire-and-forget with a ceiling so a stuck old session can never
// leak the goroutine forever (the OS reclaims the socket on process exit regardless).
const discordCloseTimeout = 10 * time.Second

// ApplyDiscord hot-reloads the Discord bot under discordMu (serialising concurrent
// saves so two Open()s can never race). The sequence is deliberately swap-LAST:
//
//  1. No-op short-circuit: if token + the three channels are identical to the LIVE
//     bot's config, return immediately. This is mandatory, not cosmetic — it avoids
//     a needless Gateway churn and a wasted identify against Discord's 1000/24h limit
//     on every save that didn't actually change Discord.
//  2. Disable case: an empty token or main channel means "Discord off". Swap the
//     holder to nil and bounded-close the old session. notifs then go silently nil.
//  3. Build + Open the NEW session FIRST (NewDiscordBot calls session.Open()). If it
//     errors, return WITHOUT swapping: the OLD session stays live, so there is no
//     notification gap, and a transiently-bad token never blanks alerting. (The
//     onboarding REST test already validated the token before we get here — this is
//     the second filter.)
//  4. Atomically publish the new bot (Swap).
//  5. Close the OLD session AFTER the swap, in a bounded goroutine. The transient
//     few-ms double session is harmless: the bot registers no inbound handlers (it
//     only sends), so nothing is double-processed.
//
// It returns an error ONLY when building/opening the new session fails (the live bot
// is untouched in that case). A nil error covers no-op, disable, and successful swap.
func (r *ServiceRegistry) ApplyDiscord(token, channelID, authChannel, ansibleChannel string) error {
	r.discordMu.Lock()
	defer r.discordMu.Unlock()

	current := r.discord.Load()

	// (1) No-op if nothing changed vs the live bot's actual config.
	if current != nil &&
		current.token == token &&
		current.channelID == channelID &&
		current.authChannelID == authChannel &&
		current.ansibleChannelID == ansibleChannel {
		return nil
	}

	// (2) Disable: empty token/channel ⇒ turn Discord off (nil holder), close old.
	if token == "" || channelID == "" {
		old := r.discord.Swap(nil)
		if old != nil {
			boundedCloseDiscord(old)
		}
		slog.Info("Discord hot-reload: disabled (no token/channel)")
		return nil
	}

	// (3) Build + Open the NEW session first. On failure, keep the old one live.
	bot, err := NewDiscordBot(token, channelID, authChannel, ansibleChannel)
	if err != nil {
		return err
	}

	// (4) Publish the new bot atomically.
	old := r.discord.Swap(bot)

	// (5) Close the previous session after the swap, bounded so a wedged Close can't leak.
	if old != nil {
		boundedCloseDiscord(old)
	}
	slog.Info("Discord hot-reload: new session live", "channel", channelID)
	return nil
}

// boundedCloseDiscord closes a replaced Discord session in its own goroutine with a
// hard time budget so a hung discordgo Close (wedged websocket) can never block the
// caller nor leak indefinitely. It is fire-and-forget by design.
func boundedCloseDiscord(b *DiscordBot) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), discordCloseTimeout)
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("Discord hot-reload: panic closing old session", "panic", rec)
				}
				close(done)
			}()
			b.Close()
		}()
		select {
		case <-done:
		case <-ctx.Done():
			slog.Warn("Discord hot-reload: old session close timed out — abandoning it")
		}
	}()
}
