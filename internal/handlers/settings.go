package handlers

import (
	"log/slog"
	"net/http"

	"goacore/internal/middleware"
	"goacore/internal/models"
)

// This file wires the unified "Paramètres" hub. Every section renders the single
// settings.html scaffold (sidebar + role-aware sub-nav + dispatched section body).
// The admin-only sections (services, utilisateurs, and the proxmox/sauvegarde
// aliases) are enforced Admin-only at the ROUTER level — settingsBase only mirrors
// that boundary into the nav rail via IsAdmin, it is never the authorization gate.

// settingsBase builds the common data map every settings section shares: the active
// section key (drives both the dispatch and the nav highlight), the role flag for the
// nav rail, the header subtitle and the username. Callers add their section-specific
// keys (cards, user list, banners…) on top.
func (h *Handler) settingsBase(r *http.Request, section, subtitle string) map[string]any {
	return map[string]any{
		"Section":        section,
		"Active":         section,
		"IsAdmin":        middleware.GetSessionRole(r, h.SessionStore) == "Admin",
		"HeaderSubtitle": subtitle,
		"User":           middleware.GetSessionUser(r, h.SessionStore),
		"Error":          "",
		"Success":        "",
	}
}

// renderSettings executes the hub scaffold with the given data map.
func (h *Handler) renderSettings(w http.ResponseWriter, data map[string]any) {
	if err := h.Templates.ExecuteTemplate(w, "settings.html", data); err != nil {
		slog.Error("Template error (settings.html)", "error", err, "section", data["Section"])
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// HandleSettingsIndex is the hub entry point (the sidebar cog → /parametres). It
// steers to the first section the current role can actually open: admins land on
// Services, everyone else on their profile (the admin sections would 403).
func (h *Handler) HandleSettingsIndex(w http.ResponseWriter, r *http.Request) {
	if middleware.GetSessionRole(r, h.SessionStore) == "Admin" {
		http.Redirect(w, r, "/parametres/services", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/parametres/profil", http.StatusSeeOther)
}

// HandleSettingsServices renders the Services section (master-detail). The actual
// view-model assembly lives in renderConnexions so the per-service POST handlers
// (save/import/delete) re-render the exact same section with a banner. Admin-only.
func (h *Handler) HandleSettingsServices(w http.ResponseWriter, r *http.Request) {
	h.renderConnexions(w, r, "", "")
}

// HandleSettingsProfil renders the "Mon profil" section (self-service, any role).
// Reachable at /parametres/profil and at the legacy /profile alias.
func (h *Handler) HandleSettingsProfil(w http.ResponseWriter, r *http.Request) {
	username := middleware.GetSessionUser(r, h.SessionStore)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var u models.User
	if err := h.DB.QueryRow("SELECT username, email, role, github_url FROM users WHERE username = ?", username).
		Scan(&u.Username, &u.Email, &u.Role, &u.GithubURL); err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	data := h.settingsBase(r, "profil", "Gérez vos informations personnelles.")
	data["Username"] = u.Username
	data["Email"] = u.Email
	data["Role"] = u.Role
	data["GithubURL"] = u.GithubURL
	h.renderSettings(w, data)
}

// HandleSettingsSecurite renders the "Sécurité (2FA)" section (self-service, any role).
func (h *Handler) HandleSettingsSecurite(w http.ResponseWriter, r *http.Request) {
	username := middleware.GetSessionUser(r, h.SessionStore)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var mfaEnabled bool
	if err := h.DB.QueryRow("SELECT mfa_enabled FROM users WHERE username = ?", username).Scan(&mfaEnabled); err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	data := h.settingsBase(r, "securite", "Protégez l'accès à votre compte.")
	data["MFAEnabled"] = mfaEnabled
	h.renderSettings(w, data)
}

// HandleSettingsUtilisateurs renders the "Utilisateurs" section (Admin-only). It lists
// the accounts; create/update/delete still POST to the existing /api/users/* endpoints.
// Reachable at /parametres/utilisateurs and at the legacy /users alias.
func (h *Handler) HandleSettingsUtilisateurs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Erreur base de données", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			slog.Error("Error scanning user", "error", err)
			continue
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Error iterating users", "error", err)
	}

	data := h.settingsBase(r, "utilisateurs", "Gérez les comptes et les accès à la plateforme.")
	data["Users"] = users
	h.renderSettings(w, data)
}
