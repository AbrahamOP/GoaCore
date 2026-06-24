package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTestWazuhIndexer_EmptyFields rejects missing inputs as a hard auth block
// before any network call.
func TestTestWazuhIndexer_EmptyFields(t *testing.T) {
	res := TestWazuhIndexer("", "u", "p", false)
	if res.OK || res.Kind != TestKindAuth {
		t.Errorf("empty URL: got %+v, want auth block", res)
	}
	res = TestWazuhIndexer("https://x:9200", "", "p", false)
	if res.OK || res.Kind != TestKindAuth {
		t.Errorf("empty user: got %+v, want auth block", res)
	}
}

// TestTestWazuhIndexer_OK hits /_cluster/health and classifies 200 as success.
func TestTestWazuhIndexer_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_cluster/health" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "secret" {
			t.Errorf("basic auth = (%q,%q,%v), want admin/secret", u, p, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := TestWazuhIndexer(srv.URL, "admin", "secret", false)
	if !res.OK {
		t.Errorf("got %+v, want OK", res)
	}
}

// TestTestWazuhIndexer_AuthFails classifies a 401 as a hard auth block.
func TestTestWazuhIndexer_AuthFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res := TestWazuhIndexer(srv.URL, "admin", "bad", false)
	if res.OK || res.Kind != TestKindAuth {
		t.Errorf("got %+v, want auth block", res)
	}
}

// TestTestWazuhIndexer_NetworkError classifies an unreachable host as a transient
// network error (the only overridable kind). It spins up a server, captures its URL,
// then closes it so the connection is refused immediately (fast, deterministic).
func TestTestWazuhIndexer_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now the port refuses connections

	res := TestWazuhIndexer(url, "u", "p", false)
	if res.OK || res.Kind != TestKindNetwork {
		t.Errorf("got %+v, want network error", res)
	}
}

// TestTestWazuhAPI_OK hits /security/user/authenticate and classifies 200 as success.
func TestTestWazuhAPI_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/security/user/authenticate" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if res := TestWazuhAPI(srv.URL, "wazuh", "wazuh", false); !res.OK {
		t.Errorf("got %+v, want OK", res)
	}
}

// TestTestAI_OllamaOK probes /api/tags for Ollama (no auth) and strips a pasted
// /api/generate path back to the daemon root.
func TestTestAI_OllamaOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("unexpected path %q, want /api/tags", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Pass the URL with a /api/generate suffix to assert it's normalised.
	if res := TestAI("ollama", srv.URL+"/api/generate", "", "mistral", "", false); !res.OK {
		t.Errorf("got %+v, want OK", res)
	}
}

// TestTestAI_OpenAINoKey rejects an OpenAI test with no key as a hard auth block,
// before any network call.
func TestTestAI_OpenAINoKey(t *testing.T) {
	res := TestAI("openai", "", "", "gpt-4", "", false)
	if res.OK || res.Kind != TestKindAuth {
		t.Errorf("got %+v, want auth block", res)
	}
}

// TestTestAI_OpenAIOK probes /models with a Bearer key.
func TestTestAI_OpenAIOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("unexpected path %q, want /models", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("Authorization = %q, want Bearer sk-test", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if res := TestAI("openai", "", "sk-test", "gpt-4", srv.URL, false); !res.OK {
		t.Errorf("got %+v, want OK", res)
	}
}

// TestTestWazuhAPI_EmptyFields rejects missing inputs as a hard auth block before any
// network call (mirrors the Indexer guard; the Wazuh API probe uses a disposable
// client so it never pollutes the shared JWT cache).
func TestTestWazuhAPI_EmptyFields(t *testing.T) {
	if res := TestWazuhAPI("", "u", "p", false); res.OK || res.Kind != TestKindAuth {
		t.Errorf("empty URL: got %+v, want auth block", res)
	}
	if res := TestWazuhAPI("https://x:55000", "u", "", false); res.OK || res.Kind != TestKindAuth {
		t.Errorf("empty pass: got %+v, want auth block", res)
	}
}

// TestTestWazuhAPI_AuthFails classifies a 401 from the JWT-mint endpoint as a hard
// auth block (so the Save gate refuses to persist a bad credential).
func TestTestWazuhAPI_AuthFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if res := TestWazuhAPI(srv.URL, "wazuh", "bad", false); res.OK || res.Kind != TestKindAuth {
		t.Errorf("got %+v, want auth block", res)
	}
}

// TestTestAI_OpenAIAuthFails classifies a 401 from /v1/models as a hard auth block
// (invalid OpenAI key).
func TestTestAI_OpenAIAuthFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if res := TestAI("openai", "", "sk-bad", "gpt-4", srv.URL, false); res.OK || res.Kind != TestKindAuth {
		t.Errorf("got %+v, want auth block", res)
	}
}

// TestTestAI_OllamaNetworkError classifies an unreachable Ollama daemon as a transient
// network error (the only overridable kind), matching the Indexer/Wazuh net path.
func TestTestAI_OllamaNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // refuse connections now
	if res := TestAI("ollama", url, "", "mistral", "", false); res.OK || res.Kind != TestKindNetwork {
		t.Errorf("got %+v, want network error", res)
	}
}

// TestTestDiscordToken_Empty rejects a blank token as a hard auth block before any
// network call (the live REST probe targets the fixed discord.com host otherwise).
func TestTestDiscordToken_Empty(t *testing.T) {
	res := TestDiscordToken("")
	if res.OK || res.Kind != TestKindAuth {
		t.Errorf("got %+v, want auth block", res)
	}
}
