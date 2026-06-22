package services

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"goacloud/internal/models"
)

// Restore-test tuning constants.
const (
	restoreVlanTag        = 99               // isolation VLAN for sandbox guests
	restoreTaskTimeout    = 20 * time.Minute // max wait for a restore task
	restorePollInterval   = 5 * time.Second
	bootSettleDelay       = 25 * time.Second       // grace period after "running" before probing
	bootWaitTimeout       = 3 * time.Minute        // max wait for the guest to reach "running"
	diskDataPctCeiling    = 85.0                   // refuse N2/N3 above this thin-pool data usage
	minLocalAvailBytes    = 5 * 1024 * 1024 * 1024 // 5 GiB headroom required on local storage
	sandboxRestoreStorage = "local-lvm"
)

// ErrRestoreTestInProgress is returned when a restore test is already running for a target.
var ErrRestoreTestInProgress = fmt.Errorf("a restore test is already running for this target")

// ErrChannelUnavailable is returned when the read-only Proxmox helper channel is
// not configured but a level needs it.
var ErrChannelUnavailable = fmt.Errorf("the Proxmox restore-test channel is not configured")

// RunRestoreTest records a restore_tests row (verdict=running), then launches a
// recover-guarded goroutine that performs the level's verification and historises
// the verdict. It returns the new test ID immediately. Only one test may run per
// target at a time.
func (s *BackupService) RunRestoreTest(targetID int, level, triggeredBy string) (int, error) {
	level = normalizeLevel(level)
	if triggeredBy == "" {
		triggeredBy = "manual"
	}

	// Load the target.
	t, err := s.loadTarget(targetID)
	if err != nil {
		return 0, fmt.Errorf("target not found: %w", err)
	}
	vmid, convErr := strconv.Atoi(t.SourceRef)
	if convErr != nil || vmid <= 0 {
		return 0, fmt.Errorf("target %d has no valid VMID (%q)", targetID, t.SourceRef)
	}

	// Anti-concurrency: claim the slot before inserting the row.
	if !s.claimTestSlot(targetID) {
		return 0, ErrRestoreTestInProgress
	}

	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO restore_tests (target_id, level, verdict, started_at, triggered_by, logs)
		 VALUES (?, ?, 'running', ?, ?, '')`,
		targetID, level, now, triggeredBy)
	if err != nil {
		s.releaseTestSlot(targetID)
		return 0, fmt.Errorf("insert restore_test: %w", err)
	}
	testID64, _ := res.LastInsertId()
	testID := int(testID64)

	go s.runRestoreTestAsync(testID, t, vmid, level)
	return testID, nil
}

// runRestoreTestAsync executes the level logic. It is recover-guarded so it can
// never crash the process, and it always releases the per-target slot.
func (s *BackupService) runRestoreTestAsync(testID int, t models.BackupTarget, vmid int, level string) {
	defer s.releaseTestSlot(t.ID)
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("restore-test: panic recovered", "test_id", testID, "panic", rec)
			s.finishTest(testID, "failed", 0, 0, fmt.Sprintf("panic interne: %v", rec))
			s.notifyRestoreTest(t.Name, 0, level, "failed", fmt.Sprintf("panic interne: %v", rec))
		}
	}()

	logs := &strings.Builder{}
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		logs.WriteString(time.Now().Format("15:04:05") + " " + line + "\n")
		slog.Info("restore-test", "test_id", testID, "msg", line)
	}

	pveType := "qemu"
	if t.TargetType == "lxc" {
		pveType = "lxc"
	}

	switch level {
	case "N1":
		s.runLevelN1(testID, t, vmid, logs, logf)
	case "N2":
		s.runLevelN2N3(testID, t, vmid, pveType, "N2", logs, logf)
	default: // N3
		s.runLevelN2N3(testID, t, vmid, pveType, "N3", logs, logf)
	}
}

// runLevelN1 verifies off-site archive integrity via the channel (no restore).
func (s *BackupService) runLevelN1(testID int, t models.BackupTarget, vmid int, logs *strings.Builder, logf func(string, ...any)) {
	logf("N1 — vérification d'intégrité off-site (cryptcheck) pour VMID %d", vmid)
	if s.channel == nil || !s.channel.Configured() {
		logf("canal Proxmox non configuré — test impossible")
		s.finishTest(testID, "failed", 0, 0, logs.String())
		s.notifyRestoreTest(t.Name, 0, "N1", "failed", "canal non configuré")
		return
	}
	ok, detail, err := s.channel.Cryptcheck(vmid)
	if err != nil {
		logf("échec cryptcheck: %v", err)
		s.finishTest(testID, "failed", 0, 0, logs.String())
		s.notifyRestoreTest(t.Name, 0, "N1", "failed", err.Error())
		return
	}
	logf("cryptcheck: %s", detail)
	verdict := "failed"
	if ok {
		verdict = "passed"
	}
	s.finishTest(testID, verdict, 0, 0, logs.String())
	s.notifyRestoreTest(t.Name, 0, "N1", verdict, detail)
}

// runLevelN2N3 restores the latest archive into an isolated sandbox guest, boots
// it, optionally runs a healthcheck (N3), measures RTO, and ALWAYS destroys the
// sandbox afterwards (deferred). level is "N2" or "N3".
func (s *BackupService) runLevelN2N3(testID int, t models.BackupTarget, vmid int, pveType, level string, logs *strings.Builder, logf func(string, ...any)) {
	cfg := s.cfg
	fail := func(detail string) {
		s.finishTest(testID, "failed", 0, 0, logs.String())
		s.notifyRestoreTest(t.Name, 0, level, "failed", detail)
	}

	if s.channel == nil || !s.channel.Configured() {
		logf("canal Proxmox non configuré — test impossible")
		fail("canal non configuré")
		return
	}

	// 1. Disk pre-flight guard.
	dataPct, avail, err := s.channel.DiskFree()
	if err != nil {
		logf("échec contrôle disque: %v", err)
		fail(err.Error())
		return
	}
	logf("disque: thin_data=%.1f%% local_avail=%s", dataPct, humanSize(avail))
	if dataPct > diskDataPctCeiling {
		logf("garde-fou disque: thin_data %.1f%% > %.1f%% — annulation", dataPct, diskDataPctCeiling)
		fail(fmt.Sprintf("disque saturé (thin_data %.1f%%)", dataPct))
		return
	}
	if avail > 0 && avail < minLocalAvailBytes {
		logf("garde-fou disque: local_avail %s < %s — annulation", humanSize(avail), humanSize(minLocalAvailBytes))
		fail(fmt.Sprintf("espace insuffisant (%s disponibles)", humanSize(avail)))
		return
	}

	// 2. Pick a free sandbox VMID via Ping (status == "absent").
	sandboxVMID, err := s.pickFreeSandboxVMID(logf)
	if err != nil {
		logf("aucun VMID sandbox libre: %v", err)
		fail(err.Error())
		return
	}
	logf("sandbox VMID retenu: %d", sandboxVMID)

	// 3. Find the latest archive volid for the target.
	archive, archiveType, archiveVMID, ok := s.latestArchiveVolID(vmid, t.Storage)
	if !ok {
		logf("aucune archive trouvée pour VMID %d", vmid)
		fail("aucune archive disponible")
		return
	}
	// M1 — defense in depth: the elected archive MUST belong to the target VMID.
	// latestArchiveVolID already filters by VMID, but a bug, a storage listing
	// quirk, or a future refactor must never let us restore an archive of another
	// guest into the sandbox. Abort the test rather than restore an incoherent
	// archive.
	if archiveVMID != vmid {
		logf("INCOHÉRENCE: archive élue VMID %d ≠ cible VMID %d — test avorté", archiveVMID, vmid)
		slog.Error("restore-test: archive/vmid mismatch", "test_id", testID, "archive_vmid", archiveVMID, "target_vmid", vmid)
		fail(fmt.Sprintf("archive incohérente (VMID %d ≠ %d)", archiveVMID, vmid))
		return
	}
	if archiveType != "" {
		pveType = archiveType
	}
	logf("archive: %s (type %s)", archive, pveType)

	// Persist the sandbox VMID early so a crash mid-test still records which slot
	// was used (and the defer below guarantees its destruction regardless).
	s.setTestSandbox(testID, sandboxVMID)

	// 4. GUARANTEED cleanup: destroy the sandbox no matter what happens next, and
	// ALWAYS release the in-process VMID reservation so the slot can be reused.
	defer func() {
		defer s.releaseSandboxVMID(sandboxVMID)
		logf("nettoyage: destruction du sandbox %d", sandboxVMID)
		upid, derr := s.proxmox.DestroyGuest(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
			cfg.ProxmoxTokenSecret, pveType, sandboxVMID)
		if derr != nil {
			logf("ATTENTION: échec destruction sandbox %d: %v", sandboxVMID, derr)
			slog.Error("restore-test: sandbox destroy failed", "test_id", testID, "vmid", sandboxVMID, "error", derr)
			s.notifyZombieSandbox(sandboxVMID, derr)
			return
		}
		if upid != "" {
			if _, werr := s.proxmox.waitForTask(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
				cfg.ProxmoxTokenSecret, upid, 5*time.Minute, restorePollInterval); werr != nil {
				logf("destruction sandbox %d: %v", sandboxVMID, werr)
				s.notifyZombieSandbox(sandboxVMID, werr)
			}
		}
	}()

	// 5. Restore into the sandbox (RTO clock starts here).
	rtoStart := time.Now()
	logf("restauration de l'archive vers le sandbox %d…", sandboxVMID)
	upid, err := s.proxmox.RestoreBackup(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, pveType, archive, sandboxVMID, sandboxRestoreStorage)
	if err != nil {
		logf("échec lancement restauration: %v", err)
		fail(err.Error())
		return
	}
	exit, err := s.proxmox.waitForTask(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, upid, restoreTaskTimeout, restorePollInterval)
	if err != nil {
		logf("restauration en échec: %v", err)
		fail(err.Error())
		return
	}
	if exit != "OK" {
		logf("restauration terminée avec un statut non-OK: %s", exit)
		fail("restauration: " + exit)
		return
	}
	logf("restauration terminée (OK)")

	// 6. Force the sandbox onto the isolation VLAN BEFORE starting it.
	if err := s.proxmox.SetGuestNetworkVlan(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, pveType, sandboxVMID, restoreVlanTag); err != nil {
		logf("échec isolation réseau VLAN %d: %v", restoreVlanTag, err)
		fail("isolation réseau: " + err.Error())
		return
	}
	logf("réseau forcé sur VLAN %d", restoreVlanTag)

	// 7. Start the sandbox and wait until it is running.
	if err := s.proxmox.PowerAction(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, pveType, strconv.Itoa(sandboxVMID), "start"); err != nil {
		logf("échec démarrage sandbox: %v", err)
		fail("démarrage: " + err.Error())
		return
	}
	if err := s.waitSandboxRunning(sandboxVMID, logf); err != nil {
		logf("le sandbox n'a pas démarré: %v", err)
		fail(err.Error())
		return
	}
	rto := int(time.Since(rtoStart).Seconds())
	logf("sandbox démarré (running) — RTO=%ds", rto)

	// Boot grace period before any healthcheck.
	time.Sleep(bootSettleDelay)

	// 8. N3 only: in-guest healthcheck via the channel.
	if level == "N3" {
		if t.HealthcheckType == "" || t.HealthcheckType == "none" || t.HealthcheckTarget == "" {
			logf("N3 sans healthcheck configuré — verdict basé sur le boot uniquement")
		} else {
			kind := "service"
			if t.HealthcheckType == "port" {
				kind = "port"
			}
			ok, detail, herr := s.channel.Healthcheck(sandboxVMID, pveType, kind, t.HealthcheckTarget)
			if herr != nil {
				logf("échec healthcheck: %v", herr)
				s.finishTest(testID, "failed", rto, sandboxVMID, logs.String())
				s.notifyRestoreTest(t.Name, sandboxVMID, level, "failed", herr.Error())
				return
			}
			logf("healthcheck (%s %s): %s", kind, t.HealthcheckTarget, detail)
			if !ok {
				s.finishTest(testID, "failed", rto, sandboxVMID, logs.String())
				s.notifyRestoreTest(t.Name, sandboxVMID, level, "failed", "healthcheck: "+detail)
				return
			}
		}
	}

	logf("verdict: PASSED")
	s.finishTest(testID, "passed", rto, sandboxVMID, logs.String())
	s.notifyRestoreTest(t.Name, sandboxVMID, level, "passed", fmt.Sprintf("RTO %ds", rto))
}

// pickFreeSandboxVMID scans the sandbox range for a VMID that is both ABSENT on
// Proxmox (Ping) AND not already reserved in-process (sandboxInUse), and reserves
// it ATOMICALLY before returning it. This closes the C2 race: two restore tests
// running concurrently on different targets can NEVER be handed the same VMID, so
// they can never restore-overwrite each other's sandbox (even with force=1).
//
// Ping performs a network round-trip; to keep that off the lock we do a two-phase
// pass: probe each candidate's Proxmox status WITHOUT the lock, then, holding the
// lock, re-check it isn't reserved and claim it atomically. The reservation must be
// released later via releaseSandboxVMID (the destroy defer does this).
func (s *BackupService) pickFreeSandboxVMID(logf func(string, ...any)) (int, error) {
	return s.pickFreeSandboxVMIDWith(s.channel.Ping, logf)
}

// pickFreeSandboxVMIDWith is the testable core of pickFreeSandboxVMID: it takes the
// Proxmox status probe as a function so the scan/atomic-reservation logic can be
// exercised without a live channel. ping reports "absent"/"running"/"stopped" or an
// error for a single VMID.
func (s *BackupService) pickFreeSandboxVMIDWith(ping func(int) (string, error), logf func(string, ...any)) (int, error) {
	for vmid := sandboxVMIDMin; vmid <= sandboxVMIDMax; vmid++ {
		// Fast skip: if already reserved in-process, don't even Ping it.
		s.testMu.Lock()
		reserved := s.sandboxInUse[vmid]
		s.testMu.Unlock()
		if reserved {
			continue
		}

		// Probe Proxmox status off the lock (network call).
		status, err := ping(vmid)
		if err != nil {
			// A transient error on one slot shouldn't abort the whole scan, but
			// log it; keep trying the next slots.
			logf("ping %d: %v", vmid, err)
			continue
		}
		if status != "absent" {
			continue
		}

		// Atomically re-check and claim under the lock: a concurrent test may have
		// reserved this same slot between our Ping and now.
		s.testMu.Lock()
		if s.sandboxInUse[vmid] {
			s.testMu.Unlock()
			continue
		}
		if s.sandboxInUse == nil {
			s.sandboxInUse = make(map[int]bool)
		}
		s.sandboxInUse[vmid] = true
		s.testMu.Unlock()
		return vmid, nil
	}
	return 0, fmt.Errorf("aucun VMID sandbox libre dans [%d,%d]", sandboxVMIDMin, sandboxVMIDMax)
}

// releaseSandboxVMID frees an atomically-reserved sandbox VMID. It is idempotent
// and safe to call from the destroy defer regardless of how the test ended.
func (s *BackupService) releaseSandboxVMID(vmid int) {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	delete(s.sandboxInUse, vmid)
}

// waitSandboxRunning polls the channel until the sandbox reports "running".
func (s *BackupService) waitSandboxRunning(vmid int, logf func(string, ...any)) error {
	deadline := time.Now().Add(bootWaitTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(restorePollInterval)
		status, err := s.channel.Ping(vmid)
		if err != nil {
			logf("ping %d (attente boot): %v", vmid, err)
			continue
		}
		if status == "running" {
			return nil
		}
	}
	return fmt.Errorf("timeout: le sandbox %d n'a pas atteint l'état running", vmid)
}

// latestArchiveVolID returns the most recent vzdump volid for vmid, its type, and
// the VMID actually carried by the elected archive entry (returned so the caller
// can assert it matches the requested vmid — see M1).
func (s *BackupService) latestArchiveVolID(vmid int, storage string) (string, string, int, bool) {
	cfg := s.cfg
	if storage == "" {
		storage = defaultBackupStorage
	}
	entries, err := s.proxmox.ListBackups(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, storage)
	if err != nil {
		slog.Error("restore-test: list backups", "vmid", vmid, "error", err)
		return "", "", 0, false
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
		return "", "", 0, false
	}
	return best.VolID, best.Type, best.VMID, true
}

// --- persistence helpers ---

// loadTarget fetches a single backup target by ID.
func (s *BackupService) loadTarget(id int) (models.BackupTarget, error) {
	var t models.BackupTarget
	err := s.db.QueryRow(
		`SELECT id, name, target_type, source_ref, storage, enabled, rpo_hours,
		        retention_count, healthcheck_type, healthcheck_target, created_at
		 FROM backup_targets WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.TargetType, &t.SourceRef, &t.Storage, &t.Enabled,
			&t.RPOHours, &t.RetentionCount, &t.HealthcheckType, &t.HealthcheckTarget, &t.CreatedAt)
	if err != nil {
		return t, err
	}
	t.Name = sanitizeName(t.Name, mustAtoi(t.SourceRef))
	return t, nil
}

// setTestSandbox records the sandbox VMID chosen for a test.
func (s *BackupService) setTestSandbox(testID, vmid int) {
	if _, err := s.db.Exec(`UPDATE restore_tests SET sandbox_vmid = ? WHERE id = ?`, vmid, testID); err != nil {
		slog.Error("restore-test: set sandbox vmid", "test_id", testID, "error", err)
	}
}

// finishTest writes the terminal verdict, RTO, sandbox and logs to a test row.
func (s *BackupService) finishTest(testID int, verdict string, rtoSec, sandboxVMID int, logs string) {
	_, err := s.db.Exec(
		`UPDATE restore_tests
		 SET verdict = ?, rto_seconds = ?, sandbox_vmid = ?, completed_at = ?, logs = ?
		 WHERE id = ?`,
		verdict, rtoSec, sandboxVMID, time.Now(), logs, testID)
	if err != nil {
		slog.Error("restore-test: finish test", "test_id", testID, "error", err)
	}
}

// notifyRestoreTest sends a Discord restore-test alert if a bot is configured.
// The network call runs in its own recover-guarded goroutine (nil-safe).
func (s *BackupService) notifyRestoreTest(target string, vmid int, level, verdict, detail string) {
	if s.discord == nil || !s.discord.IsReady() {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("restore-test: panic in Discord notification recovered", "panic", rec)
			}
		}()
		if err := s.discord.SendRestoreTestAlert(target, vmid, level, verdict, 0, detail); err != nil {
			slog.Error("restore-test: Discord notification failed", "error", err)
		}
	}()
}

// notifyZombieSandbox emits a dedicated Discord alert when a sandbox guest could
// not be destroyed (leaked). The network call runs in its own recover-guarded
// goroutine (nil-safe).
func (s *BackupService) notifyZombieSandbox(vmid int, cause error) {
	if s.discord == nil || !s.discord.IsReady() {
		return
	}
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("restore-test: panic in zombie Discord notification recovered", "panic", rec)
			}
		}()
		if err := s.discord.SendZombieSandboxAlert(vmid, detail); err != nil {
			slog.Error("restore-test: zombie Discord notification failed", "error", err)
		}
	}()
}

// RecentTests returns recent restore tests, optionally filtered by target, newest first.
func (s *BackupService) RecentTests(targetID, limit int) ([]models.RestoreTest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	base := `SELECT id, target_id, run_id, level, verdict, sandbox_vmid, rto_seconds,
		started_at, completed_at, logs, triggered_by, created_at
		FROM restore_tests`
	if targetID > 0 {
		rows, err = s.db.Query(base+` WHERE target_id = ? ORDER BY id DESC LIMIT ?`, targetID, limit)
	} else {
		rows, err = s.db.Query(base+` ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tests []models.RestoreTest
	for rows.Next() {
		var rt models.RestoreTest
		var runID sql.NullInt64
		var started, completed sql.NullTime
		var logs sql.NullString
		if err := rows.Scan(&rt.ID, &rt.TargetID, &runID, &rt.Level, &rt.Verdict,
			&rt.SandboxVMID, &rt.RTOSeconds, &started, &completed, &logs,
			&rt.TriggeredBy, &rt.CreatedAt); err != nil {
			slog.Error("restore-test: scan test", "error", err)
			continue
		}
		if runID.Valid {
			v := int(runID.Int64)
			rt.RunID = &v
		}
		if started.Valid {
			rt.StartedAt = &started.Time
		}
		if completed.Valid {
			rt.CompletedAt = &completed.Time
		}
		rt.Logs = logs.String
		tests = append(tests, rt)
	}
	return tests, rows.Err()
}

// ReconcileRunningTests marks orphaned "running" restore tests as failed (their
// driving goroutine died with a server restart).
func (s *BackupService) ReconcileRunningTests() (int64, error) {
	res, err := s.db.Exec(
		`UPDATE restore_tests
		 SET verdict = 'failed', completed_at = NOW(),
		     logs = CONCAT(COALESCE(logs,''), '\nInterrompu (redémarrage serveur)')
		 WHERE verdict = 'running'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ReconcileSandboxGuests destroys any guest actually present on the host inside
// the disposable sandbox range [9500,9599] at boot. No legitimate guest ever
// lives in that range (it is reserved exclusively for ephemeral restore tests), so
// anything found there is a leak left by a crash and must be purged before it fills
// the disk. It must run AFTER the DB reconciliation of orphaned tests.
//
// It lists guests via the Proxmox API (includeGuests), filters with isSandboxVMID
// (the same non-negotiable safety guard used everywhere), and destroys each via
// DestroyGuest (which refuses anything out of range, defense in depth). Returns the
// number of sandbox guests purged.
func (s *BackupService) ReconcileSandboxGuests() (int, error) {
	cfg := s.cfg
	stats, err := s.proxmox.GetStats(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
		cfg.ProxmoxTokenSecret, true, false)
	if err != nil {
		return 0, err
	}

	// destroy wraps the real DestroyGuest + task wait for the production path.
	destroy := func(vmid int, pveType string) error {
		upid, derr := s.proxmox.DestroyGuest(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
			cfg.ProxmoxTokenSecret, pveType, vmid)
		if derr != nil {
			return derr
		}
		if upid != "" {
			if _, werr := s.proxmox.waitForTask(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID,
				cfg.ProxmoxTokenSecret, upid, 5*time.Minute, restorePollInterval); werr != nil {
				return werr
			}
		}
		return nil
	}

	return s.reconcileSandboxGuests(stats.VMs, destroy), nil
}

// reconcileSandboxGuests is the testable core of ReconcileSandboxGuests: it filters
// the guest list to the sandbox range (the only safety-relevant decision) and calls
// destroy on each, alerting on failure. destroy MUST itself refuse anything out of
// range (DestroyGuest does), so even a filtering bug cannot touch a real guest.
// Returns the number of guests successfully purged.
func (s *BackupService) reconcileSandboxGuests(vms []models.VM, destroy func(vmid int, pveType string) error) int {
	cleaned := 0
	for _, vm := range vms {
		if !isSandboxVMID(vm.ID) {
			continue
		}
		pveType := "qemu"
		if vm.Type == "CT" {
			pveType = "lxc"
		}
		slog.Warn("restore-test: leaked sandbox guest found at boot, destroying", "vmid", vm.ID, "type", pveType)
		if err := destroy(vm.ID, pveType); err != nil {
			slog.Error("restore-test: failed to destroy leaked sandbox guest", "vmid", vm.ID, "error", err)
			s.notifyZombieSandbox(vm.ID, err)
			continue
		}
		cleaned++
	}
	return cleaned
}

// --- concurrency slot helpers ---

func (s *BackupService) claimTestSlot(targetID int) bool {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	if s.testInFlight == nil {
		s.testInFlight = make(map[int]bool)
	}
	if s.testInFlight[targetID] {
		return false
	}
	s.testInFlight[targetID] = true
	return true
}

func (s *BackupService) releaseTestSlot(targetID int) {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	delete(s.testInFlight, targetID)
}

// normalizeLevel canonicalises a requested level, defaulting to N3.
func normalizeLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "N1":
		return "N1"
	case "N2":
		return "N2"
	default:
		return "N3"
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
