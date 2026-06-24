package middleware

import (
	"net/http"
	"strings"
)

// ProxmoxConfiguredFunc reports whether the live Proxmox connection is usable.
// *config.ConfigStore.ProxmoxConfigured satisfies it; passing a func keeps the
// middleware package free of a config import (and trivially testable).
type ProxmoxConfiguredFunc func() bool

// proxmoxGatedPrefixes are the path prefixes that genuinely require a configured
// Proxmox connection. When Proxmox is unconfigured, a request to one of these is
// redirected (HTML) / 409'd (API) to the onboarding page. Everything else —
// dashboard, login, setup, profile, wazuh, static, and onboarding itself — is
// left untouched so the app stays usable on a fresh instance (non-blocking
// banner on the dashboard instead of a hard wall).
var proxmoxGatedPrefixes = []string{
	"/proxmox",
	"/backups",
	"/console",
	"/ansible",
	"/ssh",
	"/api/proxmox",
	"/api/backups",
	"/api/ansible",
	"/api/ssh",
}

// OnboardingGate redirects Proxmox-dependent pages to /onboarding/proxmox (and
// returns 409 on the matching /api/* routes) while the Proxmox connection is not
// configured. It is mounted INSIDE the authenticated group, after AuthMiddleware,
// so it only ever sees logged-in users; the onboarding routes themselves are
// Admin-only by their own router group. It never gates "/", "/login", "/setup",
// "/onboarding/*", "/static", "/profile", or "/wazuh".
func OnboardingGate(configured ProxmoxConfiguredFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if configured == nil || configured() {
			next.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path
		if !isProxmoxGated(path) {
			next.ServeHTTP(w, r)
			return
		}

		// Unconfigured + a Proxmox-dependent route: steer to onboarding.
		if isAPIPath(path) {
			http.Error(w, "Proxmox non configuré. Terminez l'onboarding (/onboarding/proxmox).", http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/onboarding/proxmox", http.StatusSeeOther)
	})
}

// isProxmoxGated reports whether path is one of the Proxmox-dependent prefixes.
func isProxmoxGated(path string) bool {
	for _, p := range proxmoxGatedPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// isAPIPath reports whether the request targets a JSON API route (so the gate
// answers with a status code rather than an HTML redirect).
func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/api/")
}
