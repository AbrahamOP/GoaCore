package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("next"))
	})
}

// TestOnboardingGate_ConfiguredPassesThrough: when Proxmox is configured the gate
// is a no-op for every path.
func TestOnboardingGate_ConfiguredPassesThrough(t *testing.T) {
	gate := OnboardingGate(func() bool { return true }, okHandler())
	for _, path := range []string{"/proxmox", "/backups", "/api/proxmox/stats", "/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("configured: path %s expected 200, got %d", path, rr.Code)
		}
	}
}

// TestOnboardingGate_UnconfiguredRedirectsPages: HTML pages redirect to onboarding.
func TestOnboardingGate_UnconfiguredRedirectsPages(t *testing.T) {
	gate := OnboardingGate(func() bool { return false }, okHandler())
	for _, path := range []string{"/proxmox", "/backups", "/console", "/ansible", "/ssh"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("unconfigured: page %s expected 303, got %d", path, rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/onboarding/proxmox" {
			t.Fatalf("page %s redirected to %q, want /onboarding/proxmox", path, loc)
		}
	}
}

// TestOnboardingGate_UnconfiguredAPI409: API routes return 409 (no HTML redirect).
func TestOnboardingGate_UnconfiguredAPI409(t *testing.T) {
	gate := OnboardingGate(func() bool { return false }, okHandler())
	for _, path := range []string{"/api/proxmox/stats", "/api/backups/runs", "/api/ssh/deploy"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("unconfigured: API %s expected 409, got %d", path, rr.Code)
		}
	}
}

// TestOnboardingGate_ExemptPaths: core/onboarding paths are never gated even when
// Proxmox is unconfigured.
func TestOnboardingGate_ExemptPaths(t *testing.T) {
	gate := OnboardingGate(func() bool { return false }, okHandler())
	exempt := []string{
		"/", "/login", "/setup", "/profile", "/wazuh",
		"/onboarding/proxmox", "/api/onboarding/proxmox/test",
		"/static/theme.js", "/report",
	}
	for _, path := range exempt {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("exempt path %s expected 200, got %d", path, rr.Code)
		}
	}
}

// TestOnboardingGate_PrefixBoundaries: a path that merely shares a prefix string
// but isn't a real sub-route must NOT be gated (e.g. /proxmoxfoo).
func TestOnboardingGate_PrefixBoundaries(t *testing.T) {
	gate := OnboardingGate(func() bool { return false }, okHandler())
	for _, path := range []string{"/proxmoxfoo", "/sshkeys-export", "/backupsx"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("non-sub-route %s should pass, got %d", path, rr.Code)
		}
	}
}

// TestOnboardingGate_NilFuncPassesThrough: a nil configured-func is treated as a
// no-op (fail open rather than lock everyone out).
func TestOnboardingGate_NilFuncPassesThrough(t *testing.T) {
	gate := OnboardingGate(nil, okHandler())
	req := httptest.NewRequest(http.MethodGet, "/proxmox", nil)
	rr := httptest.NewRecorder()
	gate.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("nil func expected pass-through 200, got %d", rr.Code)
	}
}
