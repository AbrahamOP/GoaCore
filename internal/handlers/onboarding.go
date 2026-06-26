package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"goacore/internal/config"
	"goacore/internal/middleware"
	"goacore/internal/models"
	"goacore/internal/services"
	"goacore/internal/workers"
)

// proxmoxTestRequest is the JSON body of the async "Tester la connexion" button.
// The secret travels in clear over HTTPS (already enforced) and is NEVER logged
// or persisted by the test path.
type proxmoxTestRequest struct {
	URL         string `json:"url"`
	Node        string `json:"node"`
	TokenID     string `json:"token_id"`
	TokenSecret string `json:"token_secret"`
}

// proxmoxTestResponse is returned to the browser. It carries no secret.
type proxmoxTestResponse struct {
	OK    bool     `json:"ok"`
	Kind  string   `json:"kind,omitempty"`  // "network" allows "save anyway", "auth" is a hard block
	Error string   `json:"error,omitempty"` // human-readable, secret-free
	Nodes []string `json:"nodes,omitempty"`
}

// HandleOnboardingProxmoxTest is the live-test endpoint (POST JSON). It runs
// ProxmoxService.TestConnection and returns the classified result. It persists
// NOTHING and never echoes the secret back.
func (h *Handler) HandleOnboardingProxmoxTest(w http.ResponseWriter, r *http.Request) {
	// Defense in depth: the route is already in the AdminOnly group, but re-check
	// inline so a future router refactor can't silently expose it.
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var req proxmoxTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proxmoxTestResponse{Error: "Corps de requête invalide."})
		return
	}

	// Validate URL form before hitting the network (clear, non-secret feedback).
	if err := config.ValidateURL(strings.TrimSpace(req.URL)); err != nil {
		writeJSON(w, http.StatusOK, proxmoxTestResponse{
			Kind:  services.TestKindAPI,
			Error: "URL invalide : attendez-vous à un schéma + hôte (ex. https://192.0.2.10:8006).",
		})
		return
	}

	// The form never re-sends the stored secret; if the admin tests an existing
	// connection without re-typing it, fall back to the persisted secret server-side
	// (used only for this probe, never echoed back).
	if req.TokenSecret == "" {
		if _, stored, err := h.Connections.GetProxmox(); err == nil && stored != "" {
			req.TokenSecret = stored
		}
	}

	res := h.Proxmox.TestConnection(req.URL, req.Node, req.TokenID, req.TokenSecret)
	writeJSON(w, http.StatusOK, proxmoxTestResponse{
		OK:    res.OK,
		Kind:  res.Kind,
		Error: res.Error,
		Nodes: nonEmptyNodes(res.Node),
	})
}

// HandleOnboardingProxmox serves the onboarding page (GET) and handles the Save
// (POST). The GET renders the form pre-filled with the live URL/node/token_id
// (NEVER the secret — only a secret_present flag). The POST validates, re-tests
// server-side, encrypts + persists, hot-reloads the live config, refreshes the
// SSH creds, refreshes the VM cache and writes an audit entry.
func (h *Handler) HandleOnboardingProxmox(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.handleOnboardingProxmoxSave(w, r)
		return
	}
	h.renderOnboardingProxmox(w, r, "", "")
}

// renderOnboardingProxmox renders the onboarding template. errMsg/okMsg are
// optional banners. The secret is never sent to the template.
func (h *Handler) renderOnboardingProxmox(w http.ResponseWriter, r *http.Request, errMsg, okMsg string) {
	snap := h.ConfigStore.ProxmoxSnapshot()
	env := h.ConfigStore.EnvProxmox()

	source, secretPresent := h.proxmoxSourceAndSecret()
	// The env-import button is offered when the environment carries a usable Proxmox
	// connection and the live source is not already the DB row (importing would just
	// overwrite it — use the rollback instead). Read it from the frozen env snapshot
	// (never from the cfg mirror, which a DB override may have replaced).
	envImportable := env.URL != "" && env.TokenID != "" && source != "db"
	// A DB row is in effect → expose the rollback (revert to env / clear).
	canRollback := source == "db"

	// Restore-test "Réglages avancés": render the resolved VLAN (floored to 99 when
	// unset) and the live restore_storage / crypt_remote. The sandbox bridge is its
	// OWN field (SandboxBridge), distinct from the creation bridge — the form prefills
	// it from the dedicated value (raw, so an unset field renders empty with a vmbr1
	// placeholder rather than silently echoing the creation bridge).
	data := map[string]any{
		"URL":            snap.URL,
		"Node":           snap.Node,
		"TokenID":        snap.TokenID,
		"Storage":        snap.Storage,
		"Bridge":         snap.Bridge,
		"SandboxBridge":  snap.SandboxBridge,
		"SandboxVlan":    snap.SandboxVlanTag(),
		"RestoreStorage": snap.RestoreStorage,
		"CryptRemote":    snap.CryptRemote,
		"SecretPresent":  secretPresent,
		"Configured":     snap.Configured(),
		"Source":         source, // "db" | "env" | "unconfigured"
		"EnvImportable":  envImportable,
		"EnvPresent":     env.URL != "" && env.TokenID != "",
		"CanRollback":    canRollback,
		"Error":          errMsg,
		"Success":        okMsg,
		"User":           middleware.GetSessionUser(r, h.SessionStore),
		// Settings-hub chrome: this page is re-chromed into the Paramètres hub, so it
		// feeds the shared sidebar/sub-nav. Proxmox is Admin-only ⇒ IsAdmin is true here.
		"Active":         "proxmox",
		"IsAdmin":        middleware.GetSessionRole(r, h.SessionStore) == "Admin",
		"HeaderSubtitle": "Reliez GoaCore à votre hyperviseur Proxmox VE.",
	}
	if err := h.Templates.ExecuteTemplate(w, "onboarding-proxmox.html", data); err != nil {
		slog.Error("Template error (onboarding-proxmox.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleOnboardingProxmoxSave validates and persists the connection. It is the
// only write path triggered from the UI form (the route is Admin-only; we also
// re-check inline). On success it hot-reloads the live config so VMs/console work
// without a restart.
func (h *Handler) handleOnboardingProxmoxSave(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderOnboardingProxmox(w, r, "Formulaire invalide.", "")
		return
	}

	form := models.ProxmoxConnectionForm{
		URL:         strings.TrimSpace(r.FormValue("url")),
		Node:        strings.TrimSpace(r.FormValue("node")),
		TokenID:     strings.TrimSpace(r.FormValue("token_id")),
		TokenSecret: r.FormValue("token_secret"),
		Storage:     strings.TrimSpace(r.FormValue("storage")),
		Bridge:      strings.TrimSpace(r.FormValue("bridge")),
		// "Réglages avancés" (restore-test sandbox). All optional; empty falls through
		// to the env / hard-default layer at resolution time.
		RestoreStorage: strings.TrimSpace(r.FormValue("restore_storage")),
		SandboxBridge:  strings.TrimSpace(r.FormValue("sandbox_bridge")),
		CryptRemote:    strings.TrimSpace(r.FormValue("crypt_remote")),
	}
	// sandbox_vlan: parse + validate 1-4094. A blank field means "unset" (keep the
	// env/hard default), so we only reject a non-empty, out-of-range value — never
	// persist a 0 that would read as "no isolation".
	if raw := strings.TrimSpace(r.FormValue("sandbox_vlan")); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil || v < 1 || v > 4094 {
			h.renderOnboardingProxmox(w, r, "VLAN d'isolation invalide (entier entre 1 et 4094, ou vide pour le défaut 99).", "")
			return
		}
		form.SandboxVlan = v
	}
	// "save anyway" lets an admin persist past a transient network error (the
	// server still re-tests; only a hard auth failure is non-overridable).
	force := r.FormValue("force") == "1"

	// If the secret field is blank but a secret already exists, reuse the stored
	// one (the GET never sends it back, so a no-op edit must not wipe it).
	if form.TokenSecret == "" {
		if _, stored, err := h.Connections.GetProxmox(); err == nil && stored != "" {
			form.TokenSecret = stored
		}
	}

	if err := config.ValidateURL(form.URL); err != nil {
		h.renderOnboardingProxmox(w, r, "URL Proxmox invalide (schéma + hôte requis, ex. https://192.0.2.10:8006).", "")
		return
	}
	if form.TokenID == "" || form.TokenSecret == "" {
		h.renderOnboardingProxmox(w, r, "L'identifiant et le secret du token sont requis.", "")
		return
	}

	// Mandatory server-side re-test before persisting (never trust the client's
	// earlier test). Hard block on auth; allow override only on a network error.
	res := h.Proxmox.TestConnection(form.URL, form.Node, form.TokenID, form.TokenSecret)
	if !res.OK {
		switch {
		case res.Kind == services.TestKindNetwork && force:
			// Admin chose "save anyway" on a transient error — proceed, but record
			// the degraded status for audit/ops visibility.
			slog.Warn("Proxmox onboarding: saving despite network error (operator override)",
				"user", middleware.GetSessionUser(r, h.SessionStore))
		default:
			h.renderOnboardingProxmox(w, r, "Test de connexion échoué : "+res.Error, "")
			return
		}
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	if err := h.Connections.SaveProxmox(form, user); err != nil {
		slog.Error("Proxmox onboarding: persist failed", "error", err)
		h.renderOnboardingProxmox(w, r, "Échec de l'enregistrement en base.", "")
		return
	}
	if res.Kind == services.TestKindNetwork {
		// Persisted on override: mark the live status as degraded so the next
		// successful worker tick / re-save flips it back to ok.
		_ = h.Connections.SetStatus("proxmox", "error", "network error at save (operator override)")
	}

	// Hot-reload the live connection: single atomic swap + cfg mirror + SSH creds
	// refresh (console root follows the new Proxmox immediately). The sandbox bridge
	// is a DEDICATED field (its own extra_json key) — it never folds into Bridge, so a
	// prod creation bridge can never silently become the isolation bridge.
	h.ConfigStore.ApplyProxmox(config.ProxmoxConn{
		URL:            form.URL,
		Node:           form.Node,
		TokenID:        form.TokenID,
		TokenSecret:    form.TokenSecret,
		Storage:        form.Storage,
		Bridge:         form.Bridge,
		SandboxVlan:    form.SandboxVlan,
		RestoreStorage: form.RestoreStorage,
		CryptRemote:    form.CryptRemote,
		SandboxBridge:  form.SandboxBridge,
	})

	// Populate the VM cache now so the Proxmox page is live without waiting for
	// the next worker tick. Synchronous, but cheap (single GetStats round-trip).
	workers.RefreshVMCache(h.DB, h.ConfigStore, h.Proxmox, h.ProxmoxCache, h.SSEBroker)

	go services.LogAudit(h.DB, 0, user, "Onboarding Proxmox",
		"Connexion Proxmox enregistrée ("+form.URL+", node="+safeNode(form.Node)+")", middleware.RealIP(r))

	// Isolation advisory (non-blocking): the sandbox bridge should carry the
	// routed-nowhere isolation VLAN and must NOT be the prod creation bridge. If an
	// admin explicitly set the sandbox bridge equal to the creation bridge while also
	// posing a sandbox VLAN, the (bridge,vlan) pair may land a restored prod guest on a
	// live segment when that bridge does not trunk the isolation VLAN. We still save —
	// this is the operator's call — but we surface the risk in the success banner.
	okMsg := "Connexion Proxmox enregistrée et activée."
	if form.SandboxBridge != "" && form.SandboxBridge == form.Bridge && form.SandboxVlan > 0 {
		okMsg += " Attention : le bridge sandbox est identique au bridge de création — il doit porter le VLAN d'isolation routé nulle part et ne devrait pas être le bridge de prod."
	}

	h.renderOnboardingProxmox(w, r, "", okMsg)
}

// HandleOnboardingImportEnv seeds the DB connection row from the environment in
// one explicit click, then hot-reloads from the freshly-persisted (and now
// canonical) DB values. Admin-only.
func (h *Handler) HandleOnboardingImportEnv(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := h.Connections.ImportFromEnv(h.Config); err != nil {
		h.renderOnboardingProxmox(w, r, "Import impossible : "+err.Error(), "")
		return
	}

	// Re-read the freshly-imported row (the secret was re-encrypted on the way in)
	// and apply it as the live connection so DB becomes the authoritative source.
	conn, secret, err := h.Connections.GetProxmox()
	if err != nil || conn == nil {
		h.renderOnboardingProxmox(w, r, "Import effectué mais relecture échouée.", "")
		return
	}
	storage, bridge := services.ProxmoxExtra(conn)
	restoreStorage, cryptRemote, sandboxBridge, sandboxVlan := services.ProxmoxSandboxExtra(conn)
	h.ConfigStore.ApplyProxmox(config.ProxmoxConn{
		URL:            conn.URL,
		Node:           conn.Node,
		TokenID:        conn.TokenID,
		TokenSecret:    secret,
		Storage:        storage,
		Bridge:         bridge,
		SandboxVlan:    sandboxVlan,
		RestoreStorage: restoreStorage,
		CryptRemote:    cryptRemote,
		SandboxBridge:  sandboxBridge,
	})
	workers.RefreshVMCache(h.DB, h.ConfigStore, h.Proxmox, h.ProxmoxCache, h.SSEBroker)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Proxmox", "Configuration env importée en base (source=env)", middleware.RealIP(r))

	h.renderOnboardingProxmox(w, r, "", "Configuration env importée en base et activée.")
}

// HandleOnboardingDeleteProxmox is the documented rollback: it removes the
// in-app 'proxmox' connection row so the configuration reverts to the environment
// fallback (or to "unconfigured" when no env Proxmox exists). Admin-only.
//
// After the DELETE it re-resolves the live connection in the same precedence the
// boot uses (DB > env): with the row gone, the env values frozen at boot become
// authoritative again and are re-published via ConfigStore.RollbackToEnv so the
// change takes effect immediately, without waiting for a restart. When env carried
// no Proxmox, an empty connection is published (unconfigured → the OnboardingGate
// steers Proxmox pages back here).
func (h *Handler) HandleOnboardingDeleteProxmox(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	if _, err := h.Connections.DeleteProxmox(); err != nil {
		slog.Error("Proxmox onboarding: delete failed", "error", err)
		h.renderOnboardingProxmox(w, r, "Échec de la suppression en base.", "")
		return
	}

	// Re-resolve live to the env fallback frozen at boot (DB row no longer exists).
	// Empty env ⇒ an empty connection ⇒ unconfigured (the gate steers back here).
	h.ConfigStore.RollbackToEnv()
	workers.RefreshVMCache(h.DB, h.ConfigStore, h.Proxmox, h.ProxmoxCache, h.SSEBroker)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Proxmox",
		"Connexion Proxmox en base supprimée (retour au fallback env)", middleware.RealIP(r))

	h.renderOnboardingProxmox(w, r, "", "Connexion en base supprimée — retour à la configuration d'environnement.")
}

// proxmoxSourceAndSecret reports the effective source ("db"/"env"/"unconfigured")
// and whether a secret is stored. A DB row (even with an undecipherable secret)
// counts as source "db". Falls back to "env" when env carries a connection.
func (h *Handler) proxmoxSourceAndSecret() (source string, secretPresent bool) {
	conn, secret, err := h.Connections.GetProxmox()
	if conn != nil {
		// Row exists: DB is the source. secret may be empty if undecipherable.
		return "db", err == nil && secret != ""
	}
	// No DB row: the env fallback (frozen at boot) decides. Using the frozen
	// snapshot rather than the cfg mirror is robust even right after a rollback.
	env := h.ConfigStore.EnvProxmox()
	if env.URL != "" && env.TokenID != "" {
		return "env", env.TokenSecret != ""
	}
	return "unconfigured", false
}

// nonEmptyNodes wraps a single node name into a slice (or nil), shaping the JSON
// nodes field for the UI confirmation.
func nonEmptyNodes(node string) []string {
	if node == "" {
		return nil
	}
	return []string{node}
}

// safeNode returns a placeholder for an empty node so audit lines stay readable.
func safeNode(node string) string {
	if node == "" {
		return "auto"
	}
	return node
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
