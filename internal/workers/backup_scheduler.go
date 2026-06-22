package workers

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/services"
)

// StartBackupTestScheduler runs a nightly rotation of restore tests: once per day,
// at the configured hour, it picks the single backup target most "behind" on
// testing and triggers ONE restore test for it via BackupService.RunRestoreTest
// (which owns all the safety: sandbox guards, VLAN99 isolation, guaranteed
// destroy, atomic VMID reservation). The worker NEVER touches Proxmox directly.
//
// Resilience: every tick runs inside a recover-guarded function so a panic or
// error can never kill the worker (the SOAR worker once died this way). It only
// stops on ctx.Done().
func StartBackupTestScheduler(ctx context.Context, cfg *config.Config, backup *services.BackupService, discord *services.DiscordBot) {
	if cfg == nil || backup == nil {
		slog.Error("Backup test scheduler: nil config or backup service — not starting")
		return
	}
	if !cfg.BackupTestRotationEnabled {
		slog.Info("Backup test scheduler: rotation désactivée (GOABACKUP_TEST_ROTATION_ENABLED=false)")
		return
	}

	slog.Info("Starting Backup Test Scheduler Worker...", "hour", cfg.BackupTestHour)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("Backup test scheduler stopped")
			return
		case <-ticker.C:
			runBackupRotationTick(backup, cfg.BackupTestHour)
		}
	}
}

// runBackupRotationTick is the per-tick body, fully recover-guarded so the worker
// can never die. It is a no-op outside the configured hour or once the daily test
// has already fired.
func runBackupRotationTick(backup *services.BackupService, testHour int) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("Backup test scheduler: panic recovered in tick", "panic", rec)
		}
	}()

	// Only act during the configured hour of the day.
	if time.Now().Hour() != testHour {
		return
	}

	// Daily dedup: do nothing if a scheduler-triggered test already ran today.
	already, err := backup.SchedulerTestRanToday()
	if err != nil {
		slog.Error("Backup test scheduler: dedup check failed", "error", err)
		return
	}
	if already {
		return
	}

	// Pick the most-behind enabled target and trigger one test.
	targetID, level, name, err := backup.NextRotationTarget()
	if err != nil {
		if errors.Is(err, services.ErrNoRotationTarget) {
			slog.Info("Backup test scheduler: aucune cible activée à tester — rotation ignorée")
			return
		}
		slog.Error("Backup test scheduler: sélection de la cible échouée", "error", err)
		return
	}

	testID, err := backup.RunRestoreTest(targetID, level, "scheduler")
	if err != nil {
		// In-progress is benign (a manual test is already running for this target);
		// any other error is logged but never fatal.
		if errors.Is(err, services.ErrRestoreTestInProgress) {
			slog.Info("Backup test scheduler: un test est déjà en cours pour la cible — réessai demain",
				"target_id", targetID, "name", name)
			return
		}
		slog.Error("Backup test scheduler: déclenchement du test échoué",
			"target_id", targetID, "name", name, "level", level, "error", err)
		return
	}

	// RunRestoreTest already notifies Discord per test; no double notification here.
	slog.Info("Backup test scheduler: test de restauration planifié déclenché",
		"test_id", testID, "target_id", targetID, "name", name, "level", level)
}
