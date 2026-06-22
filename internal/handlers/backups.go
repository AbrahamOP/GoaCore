package handlers

import (
	"log/slog"
	"net/http"

	"goacloud/internal/models"
)

// HandleBackupPage renders the backup management & verification dashboard.
// Admin-only (gated at the router level): it will trigger restores/destroys.
func (h *Handler) HandleBackupPage(w http.ResponseWriter, r *http.Request) {
	targets, err := h.loadBackupTargets()
	if err != nil {
		slog.Error("backup: load targets", "error", err)
	}

	data := struct {
		Targets []models.BackupTarget
	}{
		Targets: targets,
	}

	if err := h.Templates.ExecuteTemplate(w, "backups.html", data); err != nil {
		slog.Error("backup: render page", "error", err)
	}
}

// loadBackupTargets returns all configured backup targets ordered by source ref.
func (h *Handler) loadBackupTargets() ([]models.BackupTarget, error) {
	rows, err := h.DB.Query(`SELECT id, name, target_type, source_ref, storage, enabled,
		rpo_hours, retention_count, healthcheck_type, healthcheck_target, created_at
		FROM backup_targets ORDER BY source_ref`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []models.BackupTarget
	for rows.Next() {
		var t models.BackupTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.TargetType, &t.SourceRef, &t.Storage,
			&t.Enabled, &t.RPOHours, &t.RetentionCount, &t.HealthcheckType,
			&t.HealthcheckTarget, &t.CreatedAt); err != nil {
			slog.Error("backup: scan target", "error", err)
			continue
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}
