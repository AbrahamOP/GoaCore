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

	// Rotation config now lives in the DB (backup_settings), editable from the UI
	// and read live by the worker. Fall back to defaults on error.
	settings, err := h.Backup.GetSettings()
	if err != nil {
		slog.Error("backup: get settings", "error", err)
	}

	data := struct {
		Targets         []models.BackupTargetView
		Summary         models.BackupSummary
		RotationEnabled bool
		RotationHour    int
	}{
		Targets:         views,
		Summary:         summary,
		RotationEnabled: settings.RotationEnabled,
		RotationHour:    settings.RotationHour,
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

// HandleBackupTest triggers a restore test for a target (POST /api/backups/test).
// Admin-only: gated at the router level, with an inline defense-in-depth check.
// This launches a DESTRUCTIVE restore into a disposable sandbox VMID (9500-9599)
// for N2/N3. Accepts {target_id, level} as JSON or form-encoded; level defaults
// to N3. Returns the new test ID immediately (the work runs asynchronously).
func (h *Handler) HandleBackupTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	targetID := 0
	level := ""
	var body struct {
		TargetID int    `json:"target_id"`
		Level    string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.TargetID > 0 {
		targetID = body.TargetID
		level = body.Level
	}
	if targetID <= 0 {
		if v := r.FormValue("target_id"); v != "" {
			targetID, _ = strconv.Atoi(v)
		}
		if level == "" {
			level = r.FormValue("level")
		}
	}
	if targetID <= 0 {
		http.Error(w, "Invalid target_id", http.StatusBadRequest)
		return
	}

	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	if username == "" {
		username = "manual"
	}

	testID, err := h.Backup.RunRestoreTest(targetID, level, username)
	if err != nil {
		slog.Error("restore-test: trigger", "target_id", targetID, "error", err)
		if errors.Is(err, services.ErrRestoreTestInProgress) {
			http.Error(w, "Un test de restauration est déjà en cours pour cette cible", http.StatusConflict)
			return
		}
		http.Error(w, "Échec du déclenchement du test de restauration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"test_id": testID, "verdict": "running"})
}

// HandleBackupTestsList returns recent restore tests as JSON (GET /api/backups/tests).
// Optional ?target_id= filters by target; otherwise all targets (capped at 50).
func (h *Handler) HandleBackupTestsList(w http.ResponseWriter, r *http.Request) {
	targetID := 0
	if v := r.URL.Query().Get("target_id"); v != "" {
		targetID, _ = strconv.Atoi(v)
	}

	tests, err := h.Backup.RecentTests(targetID, 50)
	if err != nil {
		slog.Error("restore-test: list tests", "error", err)
		http.Error(w, "Failed to list tests", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tests)
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

// HandleBackupSettings updates the global rotation settings (POST /api/backups/settings).
// Admin-only: gated at the router level, with an inline defense-in-depth check.
// Accepts {rotation_enabled, rotation_hour} as JSON. The worker reads these live
// from the DB so the change takes effect without a redeploy.
func (h *Handler) HandleBackupSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var body struct {
		RotationEnabled bool `json:"rotation_enabled"`
		RotationHour    int  `json:"rotation_hour"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.Backup.SetSettings(body.RotationEnabled, body.RotationHour); err != nil {
		slog.Error("backup: set settings", "error", err)
		http.Error(w, "Paramètres invalides (heure 0-23)", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// HandleBackupTargetSettings updates a single target's healthcheck + retention
// (POST /api/backups/target-settings). Admin-only: gated at the router level,
// with an inline defense-in-depth check. Accepts
// {target_id, healthcheck_type, healthcheck_target, retention_count} as JSON.
func (h *Handler) HandleBackupTargetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var body struct {
		TargetID          int    `json:"target_id"`
		HealthcheckType   string `json:"healthcheck_type"`
		HealthcheckTarget string `json:"healthcheck_target"`
		RetentionCount    int    `json:"retention_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.TargetID <= 0 {
		http.Error(w, "Invalid target_id", http.StatusBadRequest)
		return
	}

	if err := h.Backup.UpdateTargetSettings(body.TargetID, body.HealthcheckType, body.HealthcheckTarget, body.RetentionCount); err != nil {
		slog.Error("backup: update target settings", "target_id", body.TargetID, "error", err)
		http.Error(w, "Paramètres de cible invalides", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}
