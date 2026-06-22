package services

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/models"
)

// defaultBackupStorage is the Proxmox storage scanned for vzdump archives.
const defaultBackupStorage = "local"

// BackupService orchestrates backup inventory, RPO evaluation and (later) restore testing.
type BackupService struct {
	db      *sql.DB
	proxmox *ProxmoxService
	cfg     *config.Config
}

// NewBackupService creates a BackupService.
func NewBackupService(db *sql.DB, proxmox *ProxmoxService, cfg *config.Config) *BackupService {
	return &BackupService{db: db, proxmox: proxmox, cfg: cfg}
}

// Dashboard lists backups from Proxmox, auto-discovers targets, and returns each
// target enriched with its latest backup and RPO status, plus a coverage summary.
func (s *BackupService) Dashboard() ([]models.BackupTargetView, models.BackupSummary, error) {
	cfg := s.cfg
	entries, err := s.proxmox.ListBackups(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, defaultBackupStorage)
	if err != nil {
		// Soft-fail: still render DB targets without fresh backup data.
		slog.Error("backup: list backups", "error", err)
	}

	// Latest archive per VMID.
	latest := make(map[int]models.BackupEntry)
	for _, e := range entries {
		if e.VMID == 0 {
			continue
		}
		if cur, ok := latest[e.VMID]; !ok || e.CTime.After(cur.CTime) {
			latest[e.VMID] = e
		}
	}

	// VM names from the existing cache.
	names := make(map[int]string)
	if rows, err := s.db.Query("SELECT vmid, name FROM vm_cache"); err == nil {
		for rows.Next() {
			var id int
			var n string
			if rows.Scan(&id, &n) == nil {
				names[id] = n
			}
		}
		rows.Close()
	}

	// Auto-discovery: ensure a target row exists for each VMID that has a backup.
	for vmid, e := range latest {
		name := names[vmid]
		if name == "" {
			name = fmt.Sprintf("VM %d", vmid)
		}
		if _, err := s.db.Exec(
			`INSERT IGNORE INTO backup_targets (name, target_type, source_ref, storage) VALUES (?, ?, ?, ?)`,
			name, e.Type, fmt.Sprintf("%d", vmid), e.Storage); err != nil {
			slog.Error("backup: upsert target", "vmid", vmid, "error", err)
		}
	}

	targets, err := s.loadTargets()
	if err != nil {
		return nil, models.BackupSummary{}, err
	}

	now := time.Now()
	views := make([]models.BackupTargetView, 0, len(targets))
	summary := models.BackupSummary{Total: len(targets)}

	for _, t := range targets {
		v := models.BackupTargetView{Target: t, RPOStatus: "none", LastBackupAtStr: "—", LastBackupSizeStr: "—", LastBackupAgeStr: "—"}
		vmid, _ := strconv.Atoi(t.SourceRef)
		if e, ok := latest[vmid]; ok {
			age := now.Sub(e.CTime)
			v.HasBackup = true
			v.LastBackupAt = e.CTime
			v.LastBackupSize = e.SizeBytes
			v.FreshnessHours = age.Hours()
			v.RPOStatus = rpoStatus(age, t.RPOHours)
			v.LastBackupAtStr = e.CTime.Format("02/01/2006 15:04")
			v.LastBackupSizeStr = humanSize(e.SizeBytes)
			v.LastBackupAgeStr = humanAge(age)
		}
		switch v.RPOStatus {
		case "ok":
			summary.OK++
		case "warn":
			summary.Warn++
		case "breach":
			summary.Breach++
		default:
			summary.None++
		}
		views = append(views, v)
	}

	summary.AtRisk = summary.Warn + summary.Breach
	if summary.Total > 0 {
		summary.CoveragePct = summary.OK * 100 / summary.Total
	}
	return views, summary, nil
}

// loadTargets returns all backup targets ordered by numeric source ref.
func (s *BackupService) loadTargets() ([]models.BackupTarget, error) {
	rows, err := s.db.Query(`SELECT id, name, target_type, source_ref, storage, enabled,
		rpo_hours, retention_count, healthcheck_type, healthcheck_target, created_at
		FROM backup_targets`)
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
	sort.Slice(targets, func(i, j int) bool {
		a, _ := strconv.Atoi(targets[i].SourceRef)
		b, _ := strconv.Atoi(targets[j].SourceRef)
		return a < b
	})
	return targets, rows.Err()
}

// rpoStatus classifies a backup age against the target RPO threshold.
func rpoStatus(age time.Duration, rpoHours int) string {
	if rpoHours <= 0 {
		return "ok"
	}
	h := age.Hours()
	switch {
	case h <= float64(rpoHours):
		return "ok"
	case h <= float64(rpoHours)*2:
		return "warn"
	default:
		return "breach"
	}
}

// humanSize formats a byte count as a human-readable string.
func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// humanAge formats a duration as a compact age (min / h / j).
func humanAge(d time.Duration) string {
	h := d.Hours()
	switch {
	case h < 1:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case h < 48:
		return fmt.Sprintf("%d h", int(h))
	default:
		return fmt.Sprintf("%d j", int(h/24))
	}
}
