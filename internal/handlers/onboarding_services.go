package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"goacloud/internal/config"
	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/services"
)

// This file is the onboarding pipeline for the registry-held services (Wazuh API,
// Wazuh Indexer, AI, Discord), served on the unified /onboarding/connexions page. All
// four quartets (Test / GET render + Save POST / ImportEnv / Delete) are now wired.
//
// Every endpoint re-checks RequireAdmin inline (defence in depth — the route group is
// already Admin-only) and the secret is NEVER returned by a GET (only a
// secret_present flag) nor echoed by a Test/Save error.

// serviceTestRequest is the JSON body of the async "Tester la connexion" button,
// shared by the per-service test endpoints. Only the fields relevant to the targeted
// service are populated by the browser; the secret travels in clear over HTTPS and is
// NEVER logged or persisted by the test path. A blank secret means "reuse the stored
// one" (resolved server-side for the probe only).
type serviceTestRequest struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
	// AI-specific
	Provider      string `json:"provider"`
	APIKey        string `json:"api_key"`
	Model         string `json:"model"`
	OpenAIBaseURL string `json:"openai_base"`
	// Discord-specific
	Token     string `json:"token"`
	ChannelID string `json:"channel_id"`
}

// serviceTestResponse is returned to the browser. It carries no secret.
type serviceTestResponse struct {
	OK    bool   `json:"ok"`
	Kind  string `json:"kind,omitempty"`  // "network" allows "save anyway", "auth" is a hard block
	Error string `json:"error,omitempty"` // human-readable, secret-free
}

// serviceCardData is the per-service view model rendered into a connection card on
// the unified page. The secret is represented ONLY by SecretPresent — its value is
// never sent to the template.
type serviceCardData struct {
	Service       string // "wazuh-indexer" | "wazuh" | "ai" | "discord"
	Configured    bool
	Status        string // "ok" | "error" | "unknown"
	Source        string // "db" | "env" | "unconfigured"
	SecretPresent bool
	EnvImportable bool
	CanRollback   bool
	LastError     string
	// Clear (non-secret) fields, prefilled from the live snapshot / DB row.
	URL              string
	User             string
	Provider         string
	Model            string
	OpenAIBaseURL    string
	ChannelID        string
	AuthChannelID    string
	AnsibleChannelID string
	// Wired reports whether this panel's backend pipeline is active yet (the others
	// render read-only until their sub-lot lands).
	Wired bool
}

// HandleOnboardingConnexions serves the unified Admin-only connections page (GET).
// POST saves are routed to per-service handlers (this page's forms target the
// per-service POST endpoints), so the page handler itself is GET-only.
func (h *Handler) HandleOnboardingConnexions(w http.ResponseWriter, r *http.Request) {
	h.renderConnexions(w, r, "", "")
}

// renderConnexions gathers every service card and renders the unified template.
// errMsg/okMsg are optional banners (set by a per-service POST that re-renders).
func (h *Handler) renderConnexions(w http.ResponseWriter, r *http.Request, errMsg, okMsg string) {
	data := map[string]any{
		"User":          middleware.GetSessionUser(r, h.SessionStore),
		"Error":         errMsg,
		"Success":       okMsg,
		"WazuhIndexer":  h.wazuhIndexerCard(),
		"Wazuh":         h.wazuhCard(),
		"AI":            h.aiCard(),
		"Discord":       h.discordCard(),
		"ProxmoxLink":   "/onboarding/proxmox",
		"ProxmoxStatus": h.proxmoxCardStatus(),
		"ChannelLink":   "/onboarding/canal",
		"ChannelStatus": h.channelCardStatus(),
	}
	if err := h.Templates.ExecuteTemplate(w, "onboarding-connexions.html", data); err != nil {
		slog.Error("Template error (onboarding-connexions.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// proxmoxCardStatus reports a short label for the Proxmox panel link on the unified
// page (Proxmox keeps its own dedicated onboarding flow this iteration).
func (h *Handler) proxmoxCardStatus() string {
	if h.ConfigStore.ProxmoxConfigured() {
		return "ok"
	}
	return "unconfigured"
}

// --- Wazuh Indexer quartet ---

// wazuhIndexerCard builds the view model for the Wazuh Indexer panel from the live
// DB row (when present) or the env seed fallback. The secret is reduced to a
// SecretPresent flag.
func (h *Handler) wazuhIndexerCard() serviceCardData {
	card := serviceCardData{Service: "wazuh-indexer", Status: "unknown", Source: "unconfigured", Wired: true}

	conn, secret, err := h.Connections.GetWazuhIndexer()
	if conn != nil {
		// A DB row exists: it is the source of truth.
		card.Source = "db"
		card.Status = conn.Status
		card.URL = conn.URL
		card.User = conn.TokenID
		card.Configured = conn.URL != "" && conn.TokenID != ""
		card.SecretPresent = err == nil && secret != ""
		card.LastError = conn.LastError
		card.CanRollback = true
		// Offer env-import only when env carries a usable Indexer AND DB isn't already
		// the live source (importing would just overwrite it — use rollback instead).
		card.EnvImportable = false
		return card
	}

	// No DB row: fall back to the env config.
	if h.Config.WazuhIndexerURL != "" {
		card.Source = "env"
		card.URL = h.Config.WazuhIndexerURL
		card.User = h.Config.WazuhIndexerUser
		card.Configured = true
		card.SecretPresent = h.Config.WazuhIndexerPass != ""
		card.EnvImportable = true
	}
	return card
}

// HandleOnboardingWazuhIndexerTest is the live-test endpoint (POST JSON). It runs
// TestWazuhIndexer with a disposable client and returns the classified result. It
// persists NOTHING and never echoes the secret.
func (h *Handler) HandleOnboardingWazuhIndexerTest(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	var req serviceTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, serviceTestResponse{Error: "Corps de requête invalide."})
		return
	}
	if err := config.ValidateURL(strings.TrimSpace(req.URL)); err != nil {
		writeJSON(w, http.StatusOK, serviceTestResponse{
			Kind:  services.TestKindAPI,
			Error: "URL invalide : schéma + hôte requis (ex. https://192.168.30.10:9200).",
		})
		return
	}
	// Reuse the stored password if the form left it blank (the GET never sends it).
	password := req.Password
	if password == "" {
		password = h.storedSecret(h.Connections.GetWazuhIndexer)
	}

	res := services.TestWazuhIndexer(req.URL, req.User, password, h.Config.SkipTLSVerify)
	writeJSON(w, http.StatusOK, serviceTestResponse{OK: res.OK, Kind: res.Kind, Error: res.Error})
}

// HandleOnboardingWazuhIndexer handles the Save (POST) for the Wazuh Indexer panel.
// It validates, re-tests server-side, encrypts + persists, hot-reloads the live
// client via the registry, records the status and writes an audit entry. On any
// outcome it re-renders the unified page with a banner. GET is not handled here (the
// unified page handler renders the panel).
func (h *Handler) HandleOnboardingWazuhIndexer(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderConnexions(w, r, "Formulaire invalide.", "")
		return
	}
	form := models.WazuhIndexerConnectionForm{
		URL:      strings.TrimSpace(r.FormValue("url")),
		User:     strings.TrimSpace(r.FormValue("user")),
		Password: r.FormValue("password"),
	}
	force := r.FormValue("force") == "1"

	// Reuse the stored password on a no-op edit (the GET never sends it back).
	if form.Password == "" {
		form.Password = h.storedSecret(h.Connections.GetWazuhIndexer)
	}

	if err := config.ValidateURL(form.URL); err != nil {
		h.renderConnexions(w, r, "URL Wazuh Indexer invalide (schéma + hôte requis, ex. https://192.168.30.10:9200).", "")
		return
	}
	if form.User == "" || form.Password == "" {
		h.renderConnexions(w, r, "L'utilisateur et le mot de passe de l'Indexer sont requis.", "")
		return
	}

	// Mandatory server-side re-test. Hard block on auth; allow override on network.
	res := services.TestWazuhIndexer(form.URL, form.User, form.Password, h.Config.SkipTLSVerify)
	if !res.OK {
		if !(res.Kind == services.TestKindNetwork && force) {
			h.renderConnexions(w, r, "Test de connexion échoué : "+res.Error, "")
			return
		}
		slog.Warn("Wazuh Indexer onboarding: saving despite network error (operator override)",
			"user", middleware.GetSessionUser(r, h.SessionStore))
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	if err := h.Connections.SaveWazuhIndexer(form, user); err != nil {
		slog.Error("Wazuh Indexer onboarding: persist failed", "error", err)
		h.renderConnexions(w, r, "Échec de l'enregistrement en base.", "")
		return
	}
	if res.Kind == services.TestKindNetwork {
		_ = h.Connections.SetStatus("wazuh-indexer", "error", "network error at save (operator override)")
	}

	// Hot-reload the live Indexer client (single atomic swap, stateless — no cleanup).
	h.Registry.ApplyIndexer(form.URL, form.User, form.Password)

	go services.LogAudit(h.DB, 0, user, "Onboarding Wazuh Indexer",
		"Connexion Wazuh Indexer enregistrée ("+form.URL+")", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Connexion Wazuh Indexer enregistrée et activée.")
}

// HandleOnboardingWazuhIndexerImportEnv seeds the DB row from the environment in one
// explicit click, then hot-reloads from the freshly-persisted (now canonical) DB
// values. Admin-only.
func (h *Handler) HandleOnboardingWazuhIndexerImportEnv(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := h.Connections.ImportFromEnvWazuhIndexer(h.Config); err != nil {
		h.renderConnexions(w, r, "Import impossible : "+err.Error(), "")
		return
	}
	conn, secret, err := h.Connections.GetWazuhIndexer()
	if err != nil || conn == nil {
		h.renderConnexions(w, r, "Import effectué mais relecture échouée.", "")
		return
	}
	h.Registry.ApplyIndexer(conn.URL, conn.TokenID, secret)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Wazuh Indexer",
		"Configuration env Indexer importée en base (source=env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Configuration env Wazuh Indexer importée en base et activée.")
}

// HandleOnboardingWazuhIndexerDelete is the rollback: it removes the in-app
// 'wazuh-indexer' row so the configuration reverts to the env fallback (or to
// unconfigured). It then re-resolves the live client in the boot precedence
// (DB > env): with the row gone, the env values are re-applied via the registry.
// Admin-only.
func (h *Handler) HandleOnboardingWazuhIndexerDelete(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if _, err := h.Connections.DeleteWazuhIndexer(); err != nil {
		slog.Error("Wazuh Indexer onboarding: delete failed", "error", err)
		h.renderConnexions(w, r, "Échec de la suppression en base.", "")
		return
	}
	// Re-apply the env fallback live (empty env ⇒ ApplyIndexer publishes nil ⇒
	// unconfigured). The env creds are read from the config (frozen at boot).
	h.Registry.ApplyIndexer(h.Config.WazuhIndexerURL, h.Config.WazuhIndexerUser, h.Config.WazuhIndexerPass)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Wazuh Indexer",
		"Connexion Wazuh Indexer en base supprimée (retour au fallback env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Connexion Wazuh Indexer en base supprimée — retour à la configuration d'environnement.")
}

// --- Wazuh API quartet ---

// wazuhCard builds the view model for the Wazuh Manager API panel from the live DB
// row (when present) or the env seed fallback. The secret is reduced to a
// SecretPresent flag.
func (h *Handler) wazuhCard() serviceCardData {
	card := serviceCardData{Service: "wazuh", Status: "unknown", Source: "unconfigured", Wired: true}

	conn, secret, err := h.Connections.GetWazuh()
	if conn != nil {
		card.Source = "db"
		card.Status = conn.Status
		card.URL = conn.URL
		card.User = conn.TokenID
		card.Configured = conn.URL != "" && conn.TokenID != ""
		card.SecretPresent = err == nil && secret != ""
		card.LastError = conn.LastError
		card.CanRollback = true
		card.EnvImportable = false
		return card
	}

	if h.Config.WazuhAPIURL != "" {
		card.Source = "env"
		card.URL = h.Config.WazuhAPIURL
		card.User = h.Config.WazuhUser
		card.Configured = true
		card.SecretPresent = h.Config.WazuhPassword != ""
		card.EnvImportable = true
	}
	return card
}

// HandleOnboardingWazuhTest is the live-test endpoint (POST JSON) for the Wazuh
// Manager API. It runs TestWazuhAPI with a DISPOSABLE client (never the shared
// JWT-caching client) and returns the classified result. It persists NOTHING and
// never echoes the secret.
func (h *Handler) HandleOnboardingWazuhTest(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	var req serviceTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, serviceTestResponse{Error: "Corps de requête invalide."})
		return
	}
	if err := config.ValidateURL(strings.TrimSpace(req.URL)); err != nil {
		writeJSON(w, http.StatusOK, serviceTestResponse{
			Kind:  services.TestKindAPI,
			Error: "URL invalide : schéma + hôte requis (ex. https://192.168.30.10:55000).",
		})
		return
	}
	password := req.Password
	if password == "" {
		password = h.storedSecret(h.Connections.GetWazuh)
	}

	res := services.TestWazuhAPI(req.URL, req.User, password, h.Config.SkipTLSVerify)
	writeJSON(w, http.StatusOK, serviceTestResponse{OK: res.OK, Kind: res.Kind, Error: res.Error})
}

// HandleOnboardingWazuh handles the Save (POST) for the Wazuh API panel: validate,
// mandatory server-side re-test, encrypt + persist, hot-reload the live client via
// ApplyWazuh (new client with an empty JWT cache, lazy re-auth — no Close), record
// status and audit. Re-renders the unified page with a banner.
func (h *Handler) HandleOnboardingWazuh(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderConnexions(w, r, "Formulaire invalide.", "")
		return
	}
	form := models.WazuhConnectionForm{
		URL:      strings.TrimSpace(r.FormValue("url")),
		User:     strings.TrimSpace(r.FormValue("user")),
		Password: r.FormValue("password"),
	}
	force := r.FormValue("force") == "1"

	if form.Password == "" {
		form.Password = h.storedSecret(h.Connections.GetWazuh)
	}

	if err := config.ValidateURL(form.URL); err != nil {
		h.renderConnexions(w, r, "URL Wazuh API invalide (schéma + hôte requis, ex. https://192.168.30.10:55000).", "")
		return
	}
	if form.User == "" || form.Password == "" {
		h.renderConnexions(w, r, "L'utilisateur et le mot de passe de l'API Wazuh sont requis.", "")
		return
	}

	res := services.TestWazuhAPI(form.URL, form.User, form.Password, h.Config.SkipTLSVerify)
	if !res.OK {
		if !(res.Kind == services.TestKindNetwork && force) {
			h.renderConnexions(w, r, "Test de connexion échoué : "+res.Error, "")
			return
		}
		slog.Warn("Wazuh API onboarding: saving despite network error (operator override)",
			"user", middleware.GetSessionUser(r, h.SessionStore))
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	if err := h.Connections.SaveWazuh(form, user); err != nil {
		slog.Error("Wazuh API onboarding: persist failed", "error", err)
		h.renderConnexions(w, r, "Échec de l'enregistrement en base.", "")
		return
	}
	if res.Kind == services.TestKindNetwork {
		_ = h.Connections.SetStatus("wazuh", "error", "network error at save (operator override)")
	}

	// Hot-reload the live Wazuh API client (fresh client, empty JWT cache, lazy auth).
	h.Registry.ApplyWazuh(form.URL, form.User, form.Password)

	go services.LogAudit(h.DB, 0, user, "Onboarding Wazuh API",
		"Connexion Wazuh API enregistrée ("+form.URL+")", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Connexion Wazuh API enregistrée et activée.")
}

// HandleOnboardingWazuhImportEnv seeds the 'wazuh' row from the environment then
// hot-reloads from the freshly-persisted DB values. Admin-only.
func (h *Handler) HandleOnboardingWazuhImportEnv(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := h.Connections.ImportFromEnvWazuh(h.Config); err != nil {
		h.renderConnexions(w, r, "Import impossible : "+err.Error(), "")
		return
	}
	conn, secret, err := h.Connections.GetWazuh()
	if err != nil || conn == nil {
		h.renderConnexions(w, r, "Import effectué mais relecture échouée.", "")
		return
	}
	h.Registry.ApplyWazuh(conn.URL, conn.TokenID, secret)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Wazuh API",
		"Configuration env Wazuh API importée en base (source=env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Configuration env Wazuh API importée en base et activée.")
}

// HandleOnboardingWazuhDelete removes the in-app 'wazuh' row and re-applies the env
// fallback live (empty env ⇒ ApplyWazuh publishes nil ⇒ unconfigured). Admin-only.
func (h *Handler) HandleOnboardingWazuhDelete(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if _, err := h.Connections.DeleteWazuh(); err != nil {
		slog.Error("Wazuh API onboarding: delete failed", "error", err)
		h.renderConnexions(w, r, "Échec de la suppression en base.", "")
		return
	}
	h.Registry.ApplyWazuh(h.Config.WazuhAPIURL, h.Config.WazuhUser, h.Config.WazuhPassword)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Wazuh API",
		"Connexion Wazuh API en base supprimée (retour au fallback env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Connexion Wazuh API en base supprimée — retour à la configuration d'environnement.")
}

// --- AI quartet ---

// aiCard builds the view model for the AI enrichment panel from the live DB row (when
// present) or the env seed fallback. provider/openai_base are non-secret; the API key
// (OpenAI only) is reduced to a SecretPresent flag.
func (h *Handler) aiCard() serviceCardData {
	card := serviceCardData{Service: "ai", Status: "unknown", Source: "unconfigured", Wired: true}

	conn, secret, err := h.Connections.GetAI()
	if conn != nil {
		provider, openaiBase := services.AIExtra(conn)
		card.Source = "db"
		card.Status = conn.Status
		card.Provider = provider
		card.URL = conn.URL
		card.Model = conn.TokenID
		card.OpenAIBaseURL = openaiBase
		// Ollama needs no key, so "configured" is provider-driven, not secret-driven.
		card.Configured = provider != ""
		card.SecretPresent = err == nil && secret != ""
		card.LastError = conn.LastError
		card.CanRollback = true
		card.EnvImportable = false
		return card
	}

	if h.Config.AIProvider != "" && (h.Config.AIURL != "" || h.Config.AIAPIKey != "" || h.Config.AIProvider == "ollama") {
		card.Source = "env"
		card.Provider = h.Config.AIProvider
		card.URL = h.Config.AIURL
		card.Model = h.Config.AIModel
		card.OpenAIBaseURL = h.Config.OpenAIBaseURL
		card.Configured = true
		card.SecretPresent = h.Config.AIAPIKey != ""
		card.EnvImportable = true
	}
	return card
}

// HandleOnboardingAITest is the live-test endpoint (POST JSON) for the AI provider.
// It probes reachability + auth WITHOUT exercising the model (Ollama /api/tags,
// OpenAI /v1/models) on a disposable client. It persists nothing and never echoes the
// key. For Ollama the URL is SSRF-relevant (admin-controlled) so it is validated;
// OpenAI targets the fixed/admin base URL with a Bearer key.
func (h *Handler) HandleOnboardingAITest(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	var req serviceTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, serviceTestResponse{Error: "Corps de requête invalide."})
		return
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	// Reuse the stored key on a blank field (OpenAI only; Ollama needs none).
	apiKey := req.APIKey
	if apiKey == "" {
		apiKey = h.storedSecret(h.Connections.GetAI)
	}

	// Validate the admin-controlled outbound URL (the only SSRF surface here is the
	// Ollama URL / a custom OpenAI base — the public OpenAI host has none).
	if provider == "openai" {
		if base := strings.TrimSpace(req.OpenAIBaseURL); base != "" {
			if err := config.ValidateURL(base); err != nil {
				writeJSON(w, http.StatusOK, serviceTestResponse{Kind: services.TestKindAPI, Error: "URL de base OpenAI invalide (schéma + hôte requis)."})
				return
			}
		}
	} else if u := strings.TrimSpace(req.URL); u != "" {
		if err := config.ValidateURL(u); err != nil {
			writeJSON(w, http.StatusOK, serviceTestResponse{Kind: services.TestKindAPI, Error: "URL Ollama invalide (schéma + hôte requis, ex. http://192.168.20.10:11434)."})
			return
		}
	}

	res := services.TestAI(provider, req.URL, apiKey, req.Model, req.OpenAIBaseURL, h.Config.SkipTLSVerify)
	writeJSON(w, http.StatusOK, serviceTestResponse{OK: res.OK, Kind: res.Kind, Error: res.Error})
}

// HandleOnboardingAI handles the Save (POST) for the AI panel: validate per provider,
// mandatory server-side re-test, encrypt + persist (provider/openai_base in
// extra_json), hot-reload via ApplyAI (NewAIClient may return nil for
// openai-without-key ⇒ AI() reports disabled, SOAR degrades cleanly), record status
// and audit. Re-renders the unified page with a banner.
func (h *Handler) HandleOnboardingAI(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderConnexions(w, r, "Formulaire invalide.", "")
		return
	}
	form := models.AIConnectionForm{
		Provider:      strings.ToLower(strings.TrimSpace(r.FormValue("provider"))),
		URL:           strings.TrimSpace(r.FormValue("url")),
		APIKey:        r.FormValue("api_key"),
		Model:         strings.TrimSpace(r.FormValue("model")),
		OpenAIBaseURL: strings.TrimSpace(r.FormValue("openai_base")),
	}
	force := r.FormValue("force") == "1"

	// Reuse the stored key when blank (OpenAI re-save without re-typing the key).
	if form.APIKey == "" {
		form.APIKey = h.storedSecret(h.Connections.GetAI)
	}

	if form.Provider != "ollama" && form.Provider != "openai" {
		h.renderConnexions(w, r, "Fournisseur IA invalide (ollama ou openai).", "")
		return
	}
	if form.Provider == "openai" {
		if form.APIKey == "" {
			h.renderConnexions(w, r, "La clé API OpenAI est requise.", "")
			return
		}
		if base := form.OpenAIBaseURL; base != "" {
			if err := config.ValidateURL(base); err != nil {
				h.renderConnexions(w, r, "URL de base OpenAI invalide (schéma + hôte requis).", "")
				return
			}
		}
	} else { // ollama
		if form.URL == "" {
			h.renderConnexions(w, r, "L'URL Ollama est requise (ex. http://192.168.20.10:11434).", "")
			return
		}
		if err := config.ValidateURL(form.URL); err != nil {
			h.renderConnexions(w, r, "URL Ollama invalide (schéma + hôte requis).", "")
			return
		}
	}

	res := services.TestAI(form.Provider, form.URL, form.APIKey, form.Model, form.OpenAIBaseURL, h.Config.SkipTLSVerify)
	if !res.OK {
		if !(res.Kind == services.TestKindNetwork && force) {
			h.renderConnexions(w, r, "Test de connexion échoué : "+res.Error, "")
			return
		}
		slog.Warn("AI onboarding: saving despite network error (operator override)",
			"user", middleware.GetSessionUser(r, h.SessionStore))
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	if err := h.Connections.SaveAI(form, user); err != nil {
		slog.Error("AI onboarding: persist failed", "error", err)
		h.renderConnexions(w, r, "Échec de l'enregistrement en base.", "")
		return
	}
	if res.Kind == services.TestKindNetwork {
		_ = h.Connections.SetStatus("ai", "error", "network error at save (operator override)")
	}

	// Hot-reload the live AI client (nil for openai-without-key ⇒ disabled).
	h.Registry.ApplyAI(form.Provider, form.URL, form.APIKey, form.Model, form.OpenAIBaseURL)

	go services.LogAudit(h.DB, 0, user, "Onboarding IA",
		"Connexion IA enregistrée (provider="+form.Provider+")", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Connexion IA enregistrée et activée.")
}

// HandleOnboardingAIImportEnv seeds the 'ai' row from the environment then hot-reloads
// from the freshly-persisted DB values. Admin-only.
func (h *Handler) HandleOnboardingAIImportEnv(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := h.Connections.ImportFromEnvAI(h.Config); err != nil {
		h.renderConnexions(w, r, "Import impossible : "+err.Error(), "")
		return
	}
	conn, secret, err := h.Connections.GetAI()
	if err != nil || conn == nil {
		h.renderConnexions(w, r, "Import effectué mais relecture échouée.", "")
		return
	}
	provider, openaiBase := services.AIExtra(conn)
	h.Registry.ApplyAI(provider, conn.URL, secret, conn.TokenID, openaiBase)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding IA",
		"Configuration env IA importée en base (source=env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Configuration env IA importée en base et activée.")
}

// HandleOnboardingAIDelete removes the in-app 'ai' row and re-applies the env fallback
// live (empty env ⇒ ApplyAI publishes a nil holder ⇒ disabled). Admin-only.
func (h *Handler) HandleOnboardingAIDelete(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if _, err := h.Connections.DeleteAI(); err != nil {
		slog.Error("AI onboarding: delete failed", "error", err)
		h.renderConnexions(w, r, "Échec de la suppression en base.", "")
		return
	}
	// Re-apply the env AI live. An empty env provider disables the service cleanly.
	h.Registry.ApplyAI(h.Config.AIProvider, h.Config.AIURL, h.Config.AIAPIKey, h.Config.AIModel, h.Config.OpenAIBaseURL)

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding IA",
		"Connexion IA en base supprimée (retour au fallback env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Connexion IA en base supprimée — retour à la configuration d'environnement.")
}

// --- Discord quartet ---

// discordCard builds the view model for the Discord bot panel from the live DB row
// (when present) or the env seed fallback. The bot token is the secret and is reduced
// to a SecretPresent flag — its value is NEVER sent to the template. channel ids are
// non-secret.
func (h *Handler) discordCard() serviceCardData {
	card := serviceCardData{Service: "discord", Status: "unknown", Source: "unconfigured", Wired: true}

	conn, secret, err := h.Connections.GetDiscord()
	if conn != nil {
		authCh, ansibleCh := services.DiscordExtra(conn)
		card.Source = "db"
		card.Status = conn.Status
		card.ChannelID = conn.TokenID
		card.AuthChannelID = authCh
		card.AnsibleChannelID = ansibleCh
		// A bot needs a token AND a main channel to be usable.
		card.Configured = conn.TokenID != "" && err == nil && secret != ""
		card.SecretPresent = err == nil && secret != ""
		card.LastError = conn.LastError
		card.CanRollback = true
		card.EnvImportable = false
		return card
	}

	if h.Config.DiscordBotToken != "" && h.Config.DiscordChannelID != "" {
		card.Source = "env"
		card.ChannelID = h.Config.DiscordChannelID
		card.AuthChannelID = h.Config.DiscordAuthChannel
		card.AnsibleChannelID = h.Config.DiscordAnsibleChannel
		card.Configured = true
		card.SecretPresent = true
		card.EnvImportable = true
	}
	return card
}

// HandleOnboardingDiscordTest is the live-test endpoint (POST JSON) for the Discord
// bot. It validates the token via the Discord REST API (GET /users/@me, Bot auth) on a
// disposable client — it NEVER opens a Gateway session (no identify burned, no socket
// leaked). It persists nothing and never echoes the token.
func (h *Handler) HandleOnboardingDiscordTest(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	var req serviceTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, serviceTestResponse{Error: "Corps de requête invalide."})
		return
	}
	// Reuse the stored token if the form left it blank (the GET never sends it).
	token := req.Token
	if token == "" {
		token = h.storedSecret(h.Connections.GetDiscord)
	}

	res := services.TestDiscordToken(token)
	writeJSON(w, http.StatusOK, serviceTestResponse{OK: res.OK, Kind: res.Kind, Error: res.Error})
}

// HandleOnboardingDiscord handles the Save (POST) for the Discord panel: validate the
// token + main channel, mandatory server-side REST re-test (hard-block on auth), encrypt
// + persist (channels in extra_json), hot-reload the live bot via ApplyDiscord (REST-
// validated, Open-new-before-swap, bounded close of the old session), record status and
// audit. ApplyDiscord can fail when opening the Gateway session even though the REST
// token test passed (transient Discord/network issue); that surfaces as a save error and
// the previous bot stays live. Re-renders the unified page with a banner.
func (h *Handler) HandleOnboardingDiscord(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderConnexions(w, r, "Formulaire invalide.", "")
		return
	}
	form := models.DiscordConnectionForm{
		Token:            strings.TrimSpace(r.FormValue("token")),
		ChannelID:        strings.TrimSpace(r.FormValue("channel_id")),
		AuthChannelID:    strings.TrimSpace(r.FormValue("auth_channel_id")),
		AnsibleChannelID: strings.TrimSpace(r.FormValue("ansible_channel_id")),
	}
	force := r.FormValue("force") == "1"

	// Reuse the stored token on a no-op edit (the GET never sends it back).
	if form.Token == "" {
		form.Token = h.storedSecret(h.Connections.GetDiscord)
	}

	// Discord has no URL to validate; the token is the credential and the main channel
	// is mandatory (a bot with no channel cannot post anything).
	if form.Token == "" {
		h.renderConnexions(w, r, "Le token du bot Discord est requis.", "")
		return
	}
	if form.ChannelID == "" {
		h.renderConnexions(w, r, "L'identifiant du salon principal est requis.", "")
		return
	}

	// Mandatory server-side re-test (REST only). Hard block on auth; allow override on
	// a transient network error (force=1) exactly like the other services.
	res := services.TestDiscordToken(form.Token)
	if !res.OK {
		if !(res.Kind == services.TestKindNetwork && force) {
			h.renderConnexions(w, r, "Test du token Discord échoué : "+res.Error, "")
			return
		}
		slog.Warn("Discord onboarding: saving despite network error (operator override)",
			"user", middleware.GetSessionUser(r, h.SessionStore))
	}

	// Hot-reload the live bot FIRST: if opening the Gateway session fails, do NOT persist
	// a config that the running instance can't actually use — surface the error and keep
	// the previous bot live. ApplyDiscord is a no-op when nothing changed.
	if err := h.Registry.ApplyDiscord(form.Token, form.ChannelID, form.AuthChannelID, form.AnsibleChannelID); err != nil {
		slog.Error("Discord onboarding: hot-reload failed", "error", err)
		h.renderConnexions(w, r, "Ouverture de la session Discord échouée : le bot précédent reste actif. Vérifiez le token et réessayez.", "")
		return
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	if err := h.Connections.SaveDiscord(form, user); err != nil {
		slog.Error("Discord onboarding: persist failed", "error", err)
		h.renderConnexions(w, r, "Bot Discord activé mais l'enregistrement en base a échoué.", "")
		return
	}
	if res.Kind == services.TestKindNetwork {
		_ = h.Connections.SetStatus("discord", "error", "network error at save (operator override)")
	}

	go services.LogAudit(h.DB, 0, user, "Onboarding Discord",
		"Connexion Discord enregistrée (salon "+form.ChannelID+")", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Bot Discord enregistré et activé.")
}

// HandleOnboardingDiscordImportEnv seeds the 'discord' row from the environment then
// hot-reloads from the freshly-persisted DB values. Admin-only.
func (h *Handler) HandleOnboardingDiscordImportEnv(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := h.Connections.ImportFromEnvDiscord(h.Config); err != nil {
		h.renderConnexions(w, r, "Import impossible : "+err.Error(), "")
		return
	}
	conn, secret, err := h.Connections.GetDiscord()
	if err != nil || conn == nil {
		h.renderConnexions(w, r, "Import effectué mais relecture échouée.", "")
		return
	}
	authCh, ansibleCh := services.DiscordExtra(conn)
	if aerr := h.Registry.ApplyDiscord(secret, conn.TokenID, authCh, ansibleCh); aerr != nil {
		slog.Error("Discord onboarding: hot-reload after import failed", "error", aerr)
		h.renderConnexions(w, r, "Config importée en base mais l'ouverture de la session Discord a échoué : "+aerr.Error(), "")
		return
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Discord",
		"Configuration env Discord importée en base (source=env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Configuration env Discord importée en base et activée.")
}

// HandleOnboardingDiscordDelete removes the in-app 'discord' row and re-applies the env
// fallback live (empty env ⇒ ApplyDiscord disables Discord ⇒ notifs go silently nil).
// Admin-only.
func (h *Handler) HandleOnboardingDiscordDelete(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if _, err := h.Connections.DeleteDiscord(); err != nil {
		slog.Error("Discord onboarding: delete failed", "error", err)
		h.renderConnexions(w, r, "Échec de la suppression en base.", "")
		return
	}
	// Re-apply the env Discord live. An empty env token/channel disables the bot cleanly
	// (ApplyDiscord swaps to nil and closes the old session). An env reopen failure is
	// logged but not fatal — the row is already gone, the live bot is at worst nil.
	if err := h.Registry.ApplyDiscord(h.Config.DiscordBotToken, h.Config.DiscordChannelID, h.Config.DiscordAuthChannel, h.Config.DiscordAnsibleChannel); err != nil {
		slog.Warn("Discord onboarding: env fallback reopen failed after delete", "error", err)
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Discord",
		"Connexion Discord en base supprimée (retour au fallback env)", middleware.RealIP(r))

	h.renderConnexions(w, r, "", "Connexion Discord en base supprimée — retour à la configuration d'environnement.")
}

// storedSecret resolves the persisted secret for a service via its Get* accessor,
// returning "" when absent or undecipherable. It is the shared "reuse the stored
// secret when the form field is blank" helper for the test/save paths — the secret
// is used only server-side and never echoed back.
func (h *Handler) storedSecret(get func() (*models.Connection, string, error)) string {
	if _, secret, err := get(); err == nil && secret != "" {
		return secret
	}
	return ""
}
