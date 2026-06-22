package handlers

import (
	"log/slog"
	"net/http"

	"goacloud/internal/models"
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
