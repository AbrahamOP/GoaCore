package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"

	"goacore/internal/models"
)

// onboardingHint is one row of the non-blocking dashboard banner: an optional
// service that is not configured yet, with a label and a link to its onboarding
// panel. Proxmox is NOT listed here — it has its own hard OnboardingGate redirect.
type onboardingHint struct {
	Label string // "Wazuh", "IA (enrichissement SOAR)", "Discord"
	Link  string // deep-link to the Connexions page
}

// onboardingHints returns the list of OPTIONAL services that are not configured yet
// (Wazuh API, AI enrichment, Discord), so the dashboard can surface a discreet,
// dismissable, NON-blocking banner inviting the admin to finish setup. It reuses the
// exact same per-service "Configured" logic as the Connexions page (wazuhCard /
// aiCard / discordCard), so the banner can never drift from that page's truth.
//
// An empty slice means everything optional is configured → no banner is rendered.
func (h *Handler) onboardingHints() []onboardingHint {
	const link = "/parametres/services"
	var hints []onboardingHint
	if !h.wazuhCard().Configured {
		hints = append(hints, onboardingHint{Label: "Wazuh (sécurité)", Link: link})
	}
	if !h.aiCard().Configured {
		hints = append(hints, onboardingHint{Label: "IA (enrichissement SOAR)", Link: link})
	}
	if !h.discordCard().Configured {
		hints = append(hints, onboardingHint{Label: "Discord (notifications)", Link: link})
	}
	return hints
}

// HandleDashboard renders the main dashboard page.
func (h *Handler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)

	apps, err := h.getApps()
	if err != nil {
		slog.Error("Error fetching apps", "error", err)
	}

	data := map[string]interface{}{
		"Apps":            apps,
		"Username":        username,
		"OnboardingHints": h.onboardingHints(),
	}
	if err := h.Templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		slog.Error("Template execution error", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}

func (h *Handler) getApps() ([]models.App, error) {
	rows, err := h.DB.Query("SELECT id, name, description, external_url, icon_url, category, health_status, health_response_ms, health_last_check, is_pinned, position FROM apps ORDER BY is_pinned DESC, position ASC, category, name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []models.App
	for rows.Next() {
		var a models.App
		var icon sql.NullString
		var healthLastChk sql.NullString
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.ExternalURL, &icon, &a.Category, &a.HealthStatus, &a.HealthRespMs, &healthLastChk, &a.IsPinned, &a.Position); err != nil {
			continue
		}
		if icon.Valid {
			a.IconURL = icon.String
		}
		if healthLastChk.Valid {
			a.HealthLastChk = healthLastChk.String
		}
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return apps, err
	}
	return apps, nil
}
