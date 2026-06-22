package services

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/models"
)

// defaultBackupStorage is the Proxmox storage scanned for vzdump archives.
const defaultBackupStorage = "local"

// ErrBackupInProgress is returned when a backup is already running for a target.
var ErrBackupInProgress = errors.New("a backup is already running for this target")

// ErrNoRotationTarget is the sentinel returned by NextRotationTarget when there is
// no enabled backup target to schedule a restore test for. It is NOT fatal: the
// scheduler logs it and waits for the next opportunity.
var ErrNoRotationTarget = errors.New("no enabled backup target available for rotation")

// sanitizeName cleans a target name coming from an untrusted source (Proxmox
// guest config / vm_cache, freely settable by a guest owner) before it is stored
// or rendered. It whitelists [A-Za-z0-9 ._-], drops anything else, trims and
// truncates to 64 characters, and falls back to "VM <vmid>" if empty.
func sanitizeName(name string, vmid int) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == ' ', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	cleaned := strings.TrimSpace(b.String())
	if len(cleaned) > 64 {
		cleaned = strings.TrimSpace(cleaned[:64])
	}
	if cleaned == "" {
		return fmt.Sprintf("VM %d", vmid)
	}
	return cleaned
}

// BackupService orchestrates backup inventory, RPO evaluation and restore testing.
type BackupService struct {
	db      *sql.DB
	proxmox *ProxmoxService
	cfg     *config.Config
	discord *DiscordBot
	channel *ProxmoxChannel

	// testInFlight tracks which target IDs currently have a restore test running,
	// to enforce one test at a time per target (anti-concurrency).
	//
	// sandboxInUse tracks which sandbox VMIDs ([9500,9599]) are currently reserved
	// by an in-flight test. It is the GLOBAL (cross-target) reservation that makes
	// it impossible for two concurrent tests on DIFFERENT targets to elect — and
	// then overwrite each other on — the same disposable VMID. Both maps are
	// protected by testMu.
	testMu       sync.Mutex
	testInFlight map[int]bool
	sandboxInUse map[int]bool
}

// NewBackupService creates a BackupService.
func NewBackupService(db *sql.DB, proxmox *ProxmoxService, cfg *config.Config) *BackupService {
	return &BackupService{
		db:           db,
		proxmox:      proxmox,
		cfg:          cfg,
		testInFlight: make(map[int]bool),
		sandboxInUse: make(map[int]bool),
	}
}

// SetDiscord wires a Discord bot for backup notifications (optional; nil-safe).
func (s *BackupService) SetDiscord(d *DiscordBot) {
	s.discord = d
}

// SetChannel wires the read-only Proxmox helper channel for restore testing
// (optional; nil-safe — the feature degrades to clear errors if absent).
func (s *BackupService) SetChannel(c *ProxmoxChannel) {
	s.channel = c
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
		// The name comes from the Proxmox guest config (vm_cache), which a guest
		// owner can freely set — sanitize before persisting.
		name := sanitizeName(names[vmid], vmid)
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

// backupPollInterval is how often the async worker polls the vzdump task status.
const backupPollInterval = 5 * time.Second

// backupTimeout caps how long a single on-demand backup may run before giving up.
const backupTimeout = 30 * time.Minute

// TriggerBackup records a manual backup run, launches an async vzdump, and returns
// the new run ID immediately. The actual dump + polling + notification happen in a
// recover-guarded goroutine so a failure can never panic the server.
func (s *BackupService) TriggerBackup(targetID int, username string) (int, error) {
	// Look up the target (vmid + type) before doing anything else.
	var vmidStr, targetType, name, storage string
	err := s.db.QueryRow(
		`SELECT source_ref, target_type, name, storage FROM backup_targets WHERE id = ?`,
		targetID).Scan(&vmidStr, &targetType, &name, &storage)
	if err != nil {
		return 0, fmt.Errorf("target not found: %w", err)
	}
	vmid, convErr := strconv.Atoi(vmidStr)
	if convErr != nil || vmid <= 0 {
		return 0, fmt.Errorf("target %d has no valid VMID (%q)", targetID, vmidStr)
	}
	// Defense in depth: rows predating sanitization (or edited directly) may hold
	// an unsafe name. Sanitize again before it flows into Discord notifications.
	name = sanitizeName(name, vmid)
	if storage == "" {
		storage = defaultBackupStorage
	}

	// Map the Proxmox guest type for the API path. Auto-discovered targets store
	// "lxc"/"qemu" already; default to qemu if unknown.
	pveType := "qemu"
	if targetType == "lxc" {
		pveType = "lxc"
	}

	// Anti-concurrency: refuse to start a second vzdump while one is still running
	// for this target. The check + insert is atomic via INSERT ... SELECT ... WHERE
	// NOT EXISTS, so two concurrent requests cannot both win the race.
	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO backup_runs (target_id, backup_type, status, started_at, source, created_by, message)
		 SELECT ?, ?, 'running', ?, 'manual', ?, ?
		 FROM DUAL
		 WHERE NOT EXISTS (
		     SELECT 1 FROM backup_runs WHERE target_id = ? AND status = 'running'
		 )`,
		targetID, "vzdump", now, username, "Sauvegarde à la demande lancée", targetID)
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return 0, ErrBackupInProgress
	}
	runID64, _ := res.LastInsertId()
	runID := int(runID64)

	go s.runBackupAsync(runID, targetID, vmid, name, pveType, storage)

	return runID, nil
}

// runBackupAsync performs the vzdump, polls until completion, updates the run row
// and notifies Discord. It is recover-guarded so it can never crash the process.
func (s *BackupService) runBackupAsync(runID, targetID, vmid int, name, pveType, storage string) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("backup: panic in async worker recovered", "run_id", runID, "panic", rec)
			s.finishRun(runID, "failed", 0, "", fmt.Sprintf("panic interne: %v", rec))
			s.notifyBackup(name, vmid, "vzdump", "failed", fmt.Sprintf("panic interne: %v", rec))
		}
	}()

	cfg := s.cfg
	s.notifyBackup(name, vmid, "vzdump", "started", "")

	upid, err := s.proxmox.CreateBackup(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, pveType, strconv.Itoa(vmid), storage)
	if err != nil {
		msg := fmt.Sprintf("Échec du déclenchement vzdump: %v", err)
		slog.Error("backup: create vzdump", "run_id", runID, "vmid", vmid, "error", err)
		s.finishRun(runID, "failed", 0, "", msg)
		s.notifyBackup(name, vmid, "vzdump", "failed", msg)
		return
	}
	slog.Info("backup: vzdump started", "run_id", runID, "vmid", vmid, "upid", upid)
	s.setRunUPID(runID, upid)

	deadline := time.Now().Add(backupTimeout)
	for {
		if time.Now().After(deadline) {
			msg := fmt.Sprintf("Timeout après %s (tâche %s toujours en cours)", backupTimeout, upid)
			slog.Error("backup: vzdump timeout", "run_id", runID, "vmid", vmid, "upid", upid)
			s.finishRun(runID, "failed", 0, "", msg)
			s.notifyBackup(name, vmid, "vzdump", "failed", msg)
			return
		}
		time.Sleep(backupPollInterval)

		status, exitStatus, statErr := s.proxmox.GetTaskStatus(cfg.ProxmoxURL, cfg.ProxmoxNode,
			cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, upid)
		if statErr != nil {
			// Transient polling error: log and keep trying until the deadline.
			slog.Warn("backup: poll task status", "run_id", runID, "upid", upid, "error", statErr)
			continue
		}
		if status == "running" {
			continue
		}
		// status == "stopped" (or anything non-running): task finished.
		if exitStatus == "OK" {
			size, archive := s.lookupLatestArchive(vmid, storage)
			msg := fmt.Sprintf("Sauvegarde terminée (tâche %s)", upid)
			slog.Info("backup: vzdump completed", "run_id", runID, "vmid", vmid, "archive", archive, "size", size)
			s.finishRun(runID, "completed", size, archive, msg)
			s.notifyBackup(name, vmid, "vzdump", "completed", msg)
		} else {
			msg := fmt.Sprintf("vzdump a échoué: %s", exitStatus)
			slog.Error("backup: vzdump failed", "run_id", runID, "vmid", vmid, "exit", exitStatus)
			s.finishRun(runID, "failed", 0, "", msg)
			s.notifyBackup(name, vmid, "vzdump", "failed", msg)
		}
		return
	}
}

// lookupLatestArchive re-queries the storage for the most recent archive of vmid,
// best-effort to fill size/path on a successful run. Errors are non-fatal.
func (s *BackupService) lookupLatestArchive(vmid int, storage string) (int64, string) {
	cfg := s.cfg
	entries, err := s.proxmox.ListBackups(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, storage)
	if err != nil {
		slog.Warn("backup: list archives after success", "vmid", vmid, "error", err)
		return 0, ""
	}
	var best models.BackupEntry
	found := false
	for _, e := range entries {
		if e.VMID != vmid {
			continue
		}
		if !found || e.CTime.After(best.CTime) {
			best = e
			found = true
		}
	}
	if !found {
		return 0, ""
	}
	return best.SizeBytes, best.VolID
}

// setRunUPID persists the Proxmox task UPID on a run as soon as it is known.
func (s *BackupService) setRunUPID(runID int, upid string) {
	if _, err := s.db.Exec(`UPDATE backup_runs SET upid = ? WHERE id = ?`, upid, runID); err != nil {
		slog.Error("backup: update run upid", "run_id", runID, "error", err)
	}
}

// ReconcileRunningRuns marks any run still flagged "running" as failed. Such rows
// are zombies: their driving goroutine was killed by a server restart, so they can
// never reach a terminal state on their own. Returns the number of runs reconciled.
func (s *BackupService) ReconcileRunningRuns() (int64, error) {
	res, err := s.db.Exec(
		`UPDATE backup_runs
		 SET status = 'failed', completed_at = NOW(), message = 'Interrompu (redémarrage serveur)'
		 WHERE status = 'running'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// finishRun updates a backup_runs row to its terminal state.
func (s *BackupService) finishRun(runID int, status string, size int64, archive, message string) {
	_, err := s.db.Exec(
		`UPDATE backup_runs
		 SET status = ?, completed_at = ?, size_bytes = ?, archive_path = ?, message = ?
		 WHERE id = ?`,
		status, time.Now(), size, archive, message, runID)
	if err != nil {
		slog.Error("backup: update run", "run_id", runID, "error", err)
	}
}

// notifyBackup sends a Discord backup alert if a bot is configured (nil-safe).
// The actual network call runs in its own recover-guarded goroutine so a slow or
// failing Discord can never sit in the critical path of finishRun / state polling.
func (s *BackupService) notifyBackup(name string, vmid int, backupType, status, details string) {
	if s.discord == nil || !s.discord.IsReady() {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("backup: panic in Discord notification recovered", "panic", rec)
			}
		}()
		if err := s.discord.SendBackupAlert(name, vmid, backupType, status, details); err != nil {
			slog.Error("backup: Discord notification failed", "error", err)
		}
	}()
}

// RecentRuns returns recent backup runs, optionally filtered by target, newest first.
func (s *BackupService) RecentRuns(targetID, limit int) ([]models.BackupRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	base := `SELECT id, target_id, backup_type, status, started_at, completed_at,
		size_bytes, archive_path, source, message, created_by, upid, created_at
		FROM backup_runs`
	if targetID > 0 {
		rows, err = s.db.Query(base+` WHERE target_id = ? ORDER BY id DESC LIMIT ?`, targetID, limit)
	} else {
		rows, err = s.db.Query(base+` ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []models.BackupRun
	for rows.Next() {
		var run models.BackupRun
		var started, completed sql.NullTime
		var archive, message, createdBy, upid sql.NullString
		var size sql.NullInt64
		if err := rows.Scan(&run.ID, &run.TargetID, &run.BackupType, &run.Status,
			&started, &completed, &size, &archive, &run.Source, &message,
			&createdBy, &upid, &run.CreatedAt); err != nil {
			slog.Error("backup: scan run", "error", err)
			continue
		}
		if started.Valid {
			run.StartedAt = &started.Time
		}
		if completed.Valid {
			run.CompletedAt = &completed.Time
		}
		run.SizeBytes = size.Int64
		run.ArchivePath = archive.String
		run.Message = message.String
		run.CreatedBy = createdBy.String
		run.UPID = upid.String
		runs = append(runs, run)
	}
	return runs, rows.Err()
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

// rotationRow is one candidate considered by the scheduled-test rotation: an
// enabled backup target and (a marker for) the age of its most recent restore
// test. lastTest.Valid is false when the target has NEVER been tested.
type rotationRow struct {
	ID              int
	Name            string
	SourceRef       string
	HealthcheckType string
}

// rotationLevel derives the restore-test level for a target from its healthcheck
// configuration: N3 (restore + boot + in-guest healthcheck) when a healthcheck is
// configured, N2 (restore + boot only) otherwise. Pure and table-testable.
func rotationLevel(healthcheckType string) string {
	t := strings.TrimSpace(strings.ToLower(healthcheckType))
	if t != "" && t != "none" {
		return "N3"
	}
	return "N2"
}

// NextRotationTarget selects the enabled backup target that is the most "behind"
// on restore testing: the one whose most recent restore_tests row is the oldest,
// with NEVER-tested targets taking absolute priority. It returns the target ID,
// the derived test level (N2/N3), and the target name.
//
// If there is no enabled target it returns ErrNoRotationTarget (a non-fatal
// sentinel the scheduler handles gracefully).
//
// SQL: LEFT JOIN each enabled target onto the MAX(created_at) of its restore
// tests; order never-tested first (last_test IS NOT NULL ⇒ 0 sorts ahead), then
// by oldest last_test ascending. Ties break on the lowest target id for a stable,
// deterministic rotation.
func (s *BackupService) NextRotationTarget() (int, string, string, error) {
	const q = `
		SELECT bt.id, bt.name, bt.source_ref, COALESCE(bt.healthcheck_type, '')
		FROM backup_targets bt
		LEFT JOIN (
		    SELECT target_id, MAX(created_at) AS last_test
		    FROM restore_tests
		    GROUP BY target_id
		) rt ON rt.target_id = bt.id
		WHERE bt.enabled = TRUE
		ORDER BY rt.last_test IS NOT NULL, rt.last_test ASC, bt.id ASC
		LIMIT 1`

	var row rotationRow
	err := s.db.QueryRow(q).Scan(&row.ID, &row.Name, &row.SourceRef, &row.HealthcheckType)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", ErrNoRotationTarget
	}
	if err != nil {
		return 0, "", "", fmt.Errorf("select rotation target: %w", err)
	}

	name := sanitizeName(row.Name, mustAtoi(row.SourceRef))
	return row.ID, rotationLevel(row.HealthcheckType), name, nil
}

// SchedulerTestRanToday reports whether a scheduler-triggered restore test has
// already been created today (server local date). It backs the scheduler's daily
// dedup so the rotation fires at most once per day even though the worker ticks
// every 60s throughout the configured hour.
func (s *BackupService) SchedulerTestRanToday() (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM restore_tests
		 WHERE triggered_by = 'scheduler' AND DATE(created_at) = CURDATE()`).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
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
