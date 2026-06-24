package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"goacore/internal/middleware"
	"goacore/internal/models"
	"goacore/internal/services"
)

// HandleAnsibleSchedules handles GET (list) and POST (create) for ansible schedules.
func (h *Handler) HandleAnsibleSchedules(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listSchedules(w, r)
	case http.MethodPost:
		h.createSchedule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleAnsibleScheduleDelete deletes a schedule by ID.
func (h *Handler) HandleAnsibleScheduleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err := h.DB.Exec("DELETE FROM ansible_schedules WHERE id = ?", req.ID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// HandleAnsibleScheduleToggle toggles enabled/disabled for a schedule.
func (h *Handler) HandleAnsibleScheduleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err := h.DB.Exec("UPDATE ansible_schedules SET enabled = NOT enabled WHERE id = ?", req.ID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "toggled"})
}

func (h *Handler) listSchedules(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT s.id, s.playbook, s.vmid, COALESCE(v.name,'?'), s.key_id,
		COALESCE(k.name,'?'), s.interval_minutes, s.remote_user, s.become, s.enabled, s.next_run,
		s.last_run, s.last_status, COALESCE(s.last_output,''), s.created_by, s.created_at
		FROM ansible_schedules s
		LEFT JOIN vm_cache v ON v.vmid = s.vmid
		LEFT JOIN ssh_keys k ON k.id = s.key_id
		ORDER BY s.created_at DESC`)
	if err != nil {
		slog.Error("List schedules error", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var schedules []models.AnsibleSchedule
	for rows.Next() {
		var s models.AnsibleSchedule
		var lastRun *time.Time
		err := rows.Scan(&s.ID, &s.Playbook, &s.VMID, &s.VMName, &s.KeyID,
			&s.KeyName, &s.IntervalMinutes, &s.RemoteUser, &s.Become, &s.Enabled, &s.NextRun,
			&lastRun, &s.LastStatus, &s.LastOutput, &s.CreatedBy, &s.CreatedAt)
		if err != nil {
			slog.Error("Scan schedule error", "error", err)
			continue
		}
		s.LastRun = lastRun
		schedules = append(schedules, s)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Error iterating schedules", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schedules)
}

func (h *Handler) createSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Playbook        string `json:"playbook"`
		VMID            int    `json:"vmid"`
		KeyID           int    `json:"key_id"`
		IntervalMinutes int    `json:"interval_minutes"`
		RemoteUser      string `json:"remote_user"`
		Become          bool   `json:"become"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	req.RemoteUser = strings.TrimSpace(req.RemoteUser)

	if req.Playbook == "" || req.VMID == 0 || req.KeyID == 0 || req.IntervalMinutes < 5 {
		http.Error(w, "Missing or invalid fields", http.StatusBadRequest)
		return
	}

	// remote_user is REQUIRED: root SSH is disabled fleet-wide (PermitRootLogin=no),
	// so a schedule must always target an explicit, non-root user. No 'root' fallback.
	if req.RemoteUser == "" {
		http.Error(w, "remote_user is required", http.StatusBadRequest)
		return
	}

	// Validate the playbook path the same way one-shot runs do, so a schedule
	// can't be used to smuggle a traversal payload past the worker.
	if _, err := resolveSafePlaybookPath(req.Playbook); err != nil {
		http.Error(w, "Invalid playbook path", http.StatusBadRequest)
		return
	}

	// Reject an invalid SSH user up front (same rule the worker enforces before
	// shelling out to ansible-playbook), so a bad value is a clear 400, not a silent
	// scheduled failure later.
	if !services.ValidRemoteUser(req.RemoteUser) {
		http.Error(w, "Invalid remote_user", http.StatusBadRequest)
		return
	}

	// Get current user
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)

	nextRun := time.Now().Add(time.Duration(req.IntervalMinutes) * time.Minute)

	_, err := h.DB.Exec(`INSERT INTO ansible_schedules (playbook, vmid, key_id, interval_minutes, remote_user, become, next_run, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, req.Playbook, req.VMID, req.KeyID, req.IntervalMinutes, req.RemoteUser, req.Become, nextRun, username)
	if err != nil {
		slog.Error("Create schedule error", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}
