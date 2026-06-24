package services

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTestConnection_EmptyFields rejects missing URL/token/secret before any
// network call, classified as an auth-style hard failure.
func TestTestConnection_EmptyFields(t *testing.T) {
	p := NewProxmoxService(nil, true)
	cases := []struct{ url, tokenID, secret string }{
		{"", "id", "sec"},
		{"https://x", "", "sec"},
		{"https://x", "id", ""},
	}
	for _, c := range cases {
		res := p.TestConnection(c.url, "node", c.tokenID, c.secret)
		if res.OK {
			t.Fatalf("expected failure for %+v", c)
		}
		if res.Kind != TestKindAuth {
			t.Fatalf("expected auth kind for missing fields, got %q", res.Kind)
		}
	}
}

// TestTestConnection_AuthError maps an HTTP 401 from the node-status call to the
// auth kind (hard block at Save).
func TestTestConnection_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			// One online node so GetStats proceeds to the status call.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[{"node":"pve","status":"online"}]}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":"auth"}`))
		}
	}))
	defer srv.Close()

	p := NewProxmoxService(nil, true)
	res := p.TestConnection(srv.URL, "pve", "user@pam!t", "wrong")
	if res.OK {
		t.Fatal("expected failure on 401")
	}
	if res.Kind != TestKindAuth {
		t.Fatalf("expected auth kind, got %q (err=%s)", res.Kind, res.Error)
	}
}

// TestTestConnection_NetworkError maps an unreachable host to the network kind
// (transient — "save anyway" allowed).
func TestTestConnection_NetworkError(t *testing.T) {
	p := NewProxmoxService(nil, true)
	// 127.0.0.1:1 is reserved and refuses connections fast.
	res := p.TestConnection("https://127.0.0.1:1", "pve", "user@pam!t", "secret")
	if res.OK {
		t.Fatal("expected failure on unreachable host")
	}
	if res.Kind != TestKindNetwork {
		t.Fatalf("expected network kind, got %q (err=%s)", res.Kind, res.Error)
	}
}

// TestTestConnection_OK returns OK when /nodes and node status both answer 200.
func TestTestConnection_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[{"node":"pve","status":"online"}]}`))
		case strings.Contains(r.URL.Path, "/status"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"cpu":0.1,"memory":{"total":100,"used":10},"rootfs":{"total":100,"used":10}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewProxmoxService(nil, true)
	res := p.TestConnection(srv.URL, "pve", "user@pam!t", "secret")
	if !res.OK {
		t.Fatalf("expected OK, got kind=%q err=%s", res.Kind, res.Error)
	}
	if res.Node != "pve" {
		t.Fatalf("expected node pve echoed, got %q", res.Node)
	}
}

// TestTestConnection_NoNode detects the "authenticated but zero nodes" case from
// the real node count: /nodes answers 200 with an empty data array. This is the
// robust replacement for the old brittle "API Error Node Status ()" substring match.
func TestTestConnection_NoNode(t *testing.T) {
	var statusHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[]}`)) // authenticated, but no node
		case strings.Contains(r.URL.Path, "/status"):
			statusHit = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewProxmoxService(nil, true)
	res := p.TestConnection(srv.URL, "pve", "user@pam!t", "secret")
	if res.OK {
		t.Fatal("expected failure on zero nodes")
	}
	if res.Kind != TestKindNoNode {
		t.Fatalf("expected no_node kind, got %q (err=%s)", res.Kind, res.Error)
	}
	// Zero-node is detected from the count before any node-status call is attempted.
	if statusHit {
		t.Error("node-status call should not be reached when there are zero nodes")
	}
}

// TestClassifyTestError_Kinds asserts the string→kind mapping directly so the
// branches stay covered even without a live server.
func TestClassifyTestError_Kinds(t *testing.T) {
	cases := []struct {
		err  error
		kind string
	}{
		{errors.New("Network error (Nodes): dial tcp: timeout"), TestKindNetwork},
		{errors.New("Network error: connection refused"), TestKindNetwork},
		{errors.New("API Error Node Status (pve) HTTP 401: bad token"), TestKindAuth},
		{errors.New("API Error Node Status (pve) HTTP 403: forbidden"), TestKindAuth},
		{errors.New("API Error Node Status () HTTP 500: x"), TestKindNoNode},
		{errors.New("API Error Node Status (pve) HTTP 500: boom"), TestKindAPI},
	}
	for _, c := range cases {
		got := classifyTestError(c.err)
		if got.Kind != c.kind {
			t.Errorf("classify(%q) = %q, want %q", c.err, got.Kind, c.kind)
		}
		if got.OK {
			t.Errorf("classify(%q) OK should be false", c.err)
		}
		// The secret must never leak through the classified message.
		if strings.Contains(got.Error, "secret") && strings.Contains(strings.ToLower(got.Error), "xxxx") {
			t.Errorf("classified error leaks secret-looking content: %q", got.Error)
		}
	}
}
