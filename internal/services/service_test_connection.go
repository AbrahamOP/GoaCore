package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file holds the live-test "bricks" for the four registry-held services
// (Wazuh API, Wazuh Indexer, AI, Discord). Each reuses the existing
// TestConnectionResult{OK,Kind,Error} contract (TestKindNetwork/Auth/API) so the
// onboarding UI and the Save gate branch on the same kinds as Proxmox.
//
// Hard rules (security/correctness):
//   - SHORT timeouts only (≤10s) — NEVER the 90s EnrichAlert timeout.
//   - A DISPOSABLE http.Client per probe — never the shared WazuhClient (would
//     pollute its JWT cache) and never the live Discord session.
//   - Redirects are NOT followed.
//   - Errors are secret-free (never embed the password/token).

// testTimeout is the wall-clock budget for any single live probe.
const testTimeout = 10 * time.Second

// disposableClient builds a throwaway HTTP client for a single probe: short
// timeout, no redirect following, and the boot TLS-verification policy. It is never
// shared and never caches anything.
func disposableClient(skipTLS bool) *http.Client {
	return &http.Client{
		Timeout: testTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS}, //nolint:gosec
		},
	}
}

// baseFromURL trims a raw URL down to scheme://host (dropping any path), matching
// what NewWazuhClient / NewWazuhIndexerClient do, so the probe hits the right API
// root regardless of a trailing path the admin pasted.
func baseFromURL(rawURL string) string {
	base := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return base
}

// classifyHTTPStatus maps an HTTP status into a TestConnectionResult kind+message.
// 401/403 is a hard auth block; any other non-2xx is a generic API error. authMsg
// lets each service phrase the auth failure in its own terms.
func classifyHTTPStatus(status int, authMsg, apiPrefix string) TestConnectionResult {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return TestConnectionResult{Kind: TestKindAuth, Error: authMsg}
	default:
		return TestConnectionResult{Kind: TestKindAPI, Error: fmt.Sprintf("%s (HTTP %d).", apiPrefix, status)}
	}
}

// netError wraps a transport-level failure as a transient network result (the only
// kind the Save gate lets an admin override with force=1). The raw transport error
// is deliberately NOT embedded (it never carries a secret, but a generic message
// keeps the surface clean and avoids leaking internal host details).
func netError(prefix string) TestConnectionResult {
	return TestConnectionResult{
		Kind:  TestKindNetwork,
		Error: fmt.Sprintf("%s : service injoignable (timeout, DNS ou TLS).", prefix),
	}
}

// TestWazuhIndexer probes the Wazuh Indexer (OpenSearch) with Basic auth against
// GET {base}/_cluster/health. A 200 proves reachability + auth; 401/403 is a hard
// block. Stateless: no client is cached.
func TestWazuhIndexer(rawURL, user, pass string, skipTLS bool) TestConnectionResult {
	if strings.TrimSpace(rawURL) == "" || strings.TrimSpace(user) == "" || strings.TrimSpace(pass) == "" {
		return TestConnectionResult{Kind: TestKindAuth, Error: "URL, utilisateur et mot de passe de l'Indexer sont requis."}
	}
	base := baseFromURL(rawURL)
	req, err := http.NewRequest(http.MethodGet, base+"/_cluster/health", nil)
	if err != nil {
		return TestConnectionResult{Kind: TestKindAPI, Error: "URL Indexer invalide."}
	}
	req.SetBasicAuth(user, pass)

	resp, err := disposableClient(skipTLS).Do(req)
	if err != nil {
		return netError("Erreur réseau (Indexer)")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return classifyHTTPStatus(resp.StatusCode,
			"Authentification Indexer refusée (HTTP 401/403) : vérifiez l'utilisateur et le mot de passe.",
			"Erreur API Indexer")
	}
	return TestConnectionResult{OK: true}
}

// TestWazuhAPI probes the Wazuh Manager API with Basic auth against
// GET {base}/security/user/authenticate (the JWT-mint endpoint). A 200 proves
// reachability + valid credentials. It uses a DISPOSABLE client so it never touches
// the shared WazuhClient's JWT cache.
func TestWazuhAPI(rawURL, user, pass string, skipTLS bool) TestConnectionResult {
	if strings.TrimSpace(rawURL) == "" || strings.TrimSpace(user) == "" || strings.TrimSpace(pass) == "" {
		return TestConnectionResult{Kind: TestKindAuth, Error: "URL, utilisateur et mot de passe Wazuh sont requis."}
	}
	base := baseFromURL(rawURL)
	req, err := http.NewRequest(http.MethodGet, base+"/security/user/authenticate", nil)
	if err != nil {
		return TestConnectionResult{Kind: TestKindAPI, Error: "URL Wazuh invalide."}
	}
	req.SetBasicAuth(user, pass)

	resp, err := disposableClient(skipTLS).Do(req)
	if err != nil {
		return netError("Erreur réseau (Wazuh API)")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return classifyHTTPStatus(resp.StatusCode,
			"Authentification Wazuh refusée (HTTP 401/403) : vérifiez l'utilisateur et le mot de passe.",
			"Erreur API Wazuh")
	}
	return TestConnectionResult{OK: true}
}

// TestAI probes the AI provider for reachability + auth, WITHOUT exercising the
// configured model (a separate "tester le modèle" probe can do that later):
//   - Ollama: GET {base}/api/tags (no auth) — 200 proves the daemon is up.
//   - OpenAI: GET {base}/v1/models with Bearer key — 200 proves the key is valid.
//
// model is accepted for a future warn-not-block "model absent" check; it is not used
// to fail the test here.
func TestAI(provider, rawURL, apiKey, model, openaiBase string, skipTLS bool) TestConnectionResult {
	client := disposableClient(skipTLS)

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai":
		if strings.TrimSpace(apiKey) == "" {
			return TestConnectionResult{Kind: TestKindAuth, Error: "Clé API OpenAI requise."}
		}
		base := strings.TrimRight(strings.TrimSpace(openaiBase), "/")
		if base == "" {
			base = "https://api.openai.com/v1"
		}
		req, err := http.NewRequest(http.MethodGet, base+"/models", nil)
		if err != nil {
			return TestConnectionResult{Kind: TestKindAPI, Error: "URL OpenAI invalide."}
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := client.Do(req)
		if err != nil {
			return netError("Erreur réseau (OpenAI)")
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			return classifyHTTPStatus(resp.StatusCode,
				"Authentification OpenAI refusée (HTTP 401/403) : vérifiez la clé API.",
				"Erreur API OpenAI")
		}
		return TestConnectionResult{OK: true}

	default: // ollama (and unknown providers default to Ollama, matching NewAIClient)
		base := strings.TrimRight(strings.TrimSpace(rawURL), "/")
		if base == "" {
			base = "http://localhost:11434"
		}
		// Strip a pasted /api/generate so we hit the daemon root /api/tags.
		if i := strings.Index(base, "/api/"); i != -1 {
			base = base[:i]
		}
		req, err := http.NewRequest(http.MethodGet, base+"/api/tags", nil)
		if err != nil {
			return TestConnectionResult{Kind: TestKindAPI, Error: "URL Ollama invalide."}
		}
		resp, err := client.Do(req)
		if err != nil {
			return netError("Erreur réseau (Ollama)")
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			return classifyHTTPStatus(resp.StatusCode,
				"Ollama a refusé la requête (HTTP 401/403).",
				"Erreur API Ollama")
		}
		return TestConnectionResult{OK: true}
	}
}

// TestDiscordToken validates a bot token via the Discord REST API
// (GET https://discord.com/api/v10/users/@me with 'Bot <token>'). It NEVER opens a
// Gateway session — that would burn an identify against the 1000/24h limit and risk
// a leaked socket. A 200 proves the token is a valid bot identity; 401 means the
// token is invalid. The host is fixed (no SSRF surface).
func TestDiscordToken(token string) TestConnectionResult {
	if strings.TrimSpace(token) == "" {
		return TestConnectionResult{Kind: TestKindAuth, Error: "Le token du bot Discord est requis."}
	}
	req, err := http.NewRequest(http.MethodGet, "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		return TestConnectionResult{Kind: TestKindAPI, Error: "Requête Discord invalide."}
	}
	req.Header.Set("Authorization", "Bot "+token)

	// Discord is a fixed public host; never skip TLS verification here.
	resp, err := disposableClient(false).Do(req)
	if err != nil {
		return netError("Erreur réseau (Discord)")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return classifyHTTPStatus(resp.StatusCode,
			"Token Discord invalide (HTTP 401/403).",
			"Erreur API Discord")
	}
	return TestConnectionResult{OK: true}
}
