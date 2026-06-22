package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/services"
)

// HandleBackupPage renders the backup management & verification dashboard.
// Admin-only (gated at the router level): it will trigger restores/destroys.
// It lists the latest backups from Proxmox, auto-discovers targets and shows
// each one's RPO freshness status (N1 integrity check).
func (h *Handler) HandleBackupPage(w http.ResponseWriter, r *http.Request) {
	views, summary, err := h.Backup.Dashboard()
	if err != nil {
		slog.Error("backup: dashboard", "error", err)
	}

	data := struct {
		Targets []models.BackupTargetView
		Summary models.BackupSummary
	}{
		Targets: views,
		Summary: summary,
	}

	if err := h.Templates.ExecuteTemplate(w, "backups.html", data); err != nil {
		slog.Error("backup: render page", "error", err)
	}
}

// HandleBackupCreate triggers an on-demand vzdump for a target (POST /api/backups/create).
// Admin-only: gated at the router level, with an inline defense-in-depth check.
// Accepts {target_id} as JSON or form-encoded. Returns the new run ID immediately.
func (h *Handler) HandleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	// Read target_id from JSON body or form value.
	targetID := 0
	var body struct {
		TargetID int `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.TargetID > 0 {
		targetID = body.TargetID
	} else if v := r.FormValue("target_id"); v != "" {
		targetID, _ = strconv.Atoi(v)
	}
	if targetID <= 0 {
		http.Error(w, "Invalid target_id", http.StatusBadRequest)
		return
	}

	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)

	runID, err := h.Backup.TriggerBackup(targetID, username)
	if err != nil {
		slog.Error("backup: trigger", "target_id", targetID, "error", err)
		if errors.Is(err, services.ErrBackupInProgress) {
			http.Error(w, "Une sauvegarde est déjà en cours pour cette cible", http.StatusConflict)
			return
		}
		// Generic message to the client; the detail is already logged above.
		http.Error(w, "Échec du déclenchement de la sauvegarde", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"run_id": runID, "status": "running"})
}

// HandleBackupRunsList returns recent backup runs as JSON (GET /api/backups/runs).
// Optional ?target_id= filters by target; otherwise all targets (capped at 50).
func (h *Handler) HandleBackupRunsList(w http.ResponseWriter, r *http.Request) {
	targetID := 0
	if v := r.URL.Query().Get("target_id"); v != "" {
		targetID, _ = strconv.Atoi(v)
	}

	runs, err := h.Backup.RecentRuns(targetID, 50)
	if err != nil {
		slog.Error("backup: list runs", "error", err)
		http.Error(w, "Failed to list runs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(runs)
}
