package database

import (
	"database/sql"
	"log/slog"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"goacore/internal/config"
)

// Connect opens the database connection with retry logic.
func Connect(cfg *config.Config) (*sql.DB, error) {
	mysqlCfg := mysql.Config{
		User:                 cfg.DBUser,
		Passwd:               cfg.DBPass,
		Net:                  "tcp",
		Addr:                 cfg.DBHost,
		DBName:               cfg.DBName,
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	var db *sql.DB
	var err error
	for i := 0; i < 30; i++ {
		db, err = sql.Open("mysql", mysqlCfg.FormatDSN())
		if err == nil {
			err = db.Ping()
			if err == nil {
				break
			}
		}
		slog.Info("Waiting for database...", "attempt", i+1)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// Migrate runs auto-migrations to ensure all required tables and columns exist.
func Migrate(db *sql.DB) {
	coreTables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS apps (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			description TEXT,
			external_url VARCHAR(255) NOT NULL,
			icon_url VARCHAR(255),
			category VARCHAR(50) DEFAULT 'General',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS vm_cache (
			vmid INT PRIMARY KEY,
			name VARCHAR(255),
			ip_address VARCHAR(45),
			vm_type VARCHAR(10),
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			key_type VARCHAR(20) DEFAULT 'RSA',
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			fingerprint VARCHAR(100),
			associated_vms TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS soar_config (
			id INT PRIMARY KEY DEFAULT 1,
			alert_status BOOLEAN DEFAULT TRUE,
			alert_ssh BOOLEAN DEFAULT TRUE,
			alert_sudo BOOLEAN DEFAULT TRUE,
			alert_fim BOOLEAN DEFAULT TRUE,
			alert_packages BOOLEAN DEFAULT TRUE
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT,
			username VARCHAR(255),
			action VARCHAR(255),
			details TEXT,
			ip_address VARCHAR(255),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_host_keys (
			ip VARCHAR(255) PRIMARY KEY,
			host_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS metrics_history (
			id INT AUTO_INCREMENT PRIMARY KEY,
			cpu INT NOT NULL,
			ram INT NOT NULL,
			storage INT NOT NULL,
			recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_recorded_at (recorded_at)
		)`,
		`CREATE TABLE IF NOT EXISTS favorites (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			item_type VARCHAR(20) NOT NULL,
			item_id VARCHAR(50) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uk_fav (user_id, item_type, item_id)
		)`,
		`CREATE TABLE IF NOT EXISTS ansible_schedules (
			id INT AUTO_INCREMENT PRIMARY KEY,
			playbook VARCHAR(255) NOT NULL,
			vmid INT NOT NULL,
			key_id INT NOT NULL,
			interval_minutes INT NOT NULL,
			remote_user VARCHAR(50) NOT NULL DEFAULT 'root',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			next_run DATETIME NOT NULL,
			last_run DATETIME NULL,
			last_status VARCHAR(20) DEFAULT 'pending',
			last_output TEXT,
			created_by VARCHAR(50),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS backup_targets (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			target_type VARCHAR(10) NOT NULL DEFAULT 'qemu',
			source_ref VARCHAR(50) NOT NULL,
			storage VARCHAR(100) NOT NULL DEFAULT 'local',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			rpo_hours INT NOT NULL DEFAULT 24,
			schedule_cron VARCHAR(100) NOT NULL DEFAULT '',
			retention_count INT NOT NULL DEFAULT 3,
			healthcheck_type VARCHAR(20) NOT NULL DEFAULT 'none',
			healthcheck_target VARCHAR(255) NOT NULL DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uk_target (target_type, source_ref)
		)`,
		`CREATE TABLE IF NOT EXISTS backup_runs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			target_id INT NOT NULL,
			backup_type VARCHAR(20) NOT NULL DEFAULT 'vzdump',
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			started_at DATETIME NULL,
			completed_at DATETIME NULL,
			size_bytes BIGINT NOT NULL DEFAULT 0,
			archive_path VARCHAR(512) NOT NULL DEFAULT '',
			checksum VARCHAR(128) NOT NULL DEFAULT '',
			source VARCHAR(20) NOT NULL DEFAULT 'manual',
			message TEXT,
			created_by VARCHAR(50),
			upid VARCHAR(255) NOT NULL DEFAULT '',
			destination VARCHAR(20) NOT NULL DEFAULT 'local',
			remote VARCHAR(64) NOT NULL DEFAULT '',
			push_status VARCHAR(20) NOT NULL DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_bruns_target (target_id),
			INDEX idx_bruns_status (status),
			INDEX idx_bruns_created (created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS backup_settings (
			id INT PRIMARY KEY DEFAULT 1,
			rotation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			rotation_hour INT NOT NULL DEFAULT 4
		)`,
		`CREATE TABLE IF NOT EXISTS restore_tests (
			id INT AUTO_INCREMENT PRIMARY KEY,
			target_id INT NOT NULL,
			run_id INT NULL,
			level VARCHAR(4) NOT NULL DEFAULT 'N1',
			verdict VARCHAR(20) NOT NULL DEFAULT 'pending',
			sandbox_vmid INT NOT NULL DEFAULT 0,
			rto_seconds INT NOT NULL DEFAULT 0,
			started_at DATETIME NULL,
			completed_at DATETIME NULL,
			logs TEXT,
			triggered_by VARCHAR(20) NOT NULL DEFAULT 'manual',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_rtests_target (target_id),
			INDEX idx_rtests_verdict (verdict),
			INDEX idx_rtests_created (created_at)
		)`,
		// connections holds per-service infrastructure credentials, configured
		// in-app (onboarding) instead of (or on top of) environment variables.
		// One row per service ('proxmox' at Jalon 1; 'wazuh'/'ai'/'discord' later
		// are simply more rows — no schema change). Only the secret column is
		// encrypted (AES-256-GCM, same key as SSH keys); url/node/token_id and the
		// non-sensitive extra_json fields stay in clear. The ABSENCE of a row is the
		// "not configured" signal — there is deliberately NO INSERT IGNORE here.
		`CREATE TABLE IF NOT EXISTS connections (
			service        VARCHAR(32)  NOT NULL PRIMARY KEY,
			enabled        TINYINT(1)   NOT NULL DEFAULT 1,
			url            VARCHAR(512) NOT NULL DEFAULT '',
			node           VARCHAR(128) NOT NULL DEFAULT '',
			token_id       VARCHAR(256) NOT NULL DEFAULT '',
			secret_enc     TEXT         NOT NULL,
			extra_json     JSON         NULL,
			configured     TINYINT(1)   NOT NULL DEFAULT 0,
			status         VARCHAR(16)  NOT NULL DEFAULT 'unknown',
			last_tested_at DATETIME     NULL,
			last_error     VARCHAR(512) NOT NULL DEFAULT '',
			source         VARCHAR(8)   NOT NULL DEFAULT 'db',
			updated_by     VARCHAR(128) NOT NULL DEFAULT '',
			updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, stmt := range coreTables {
		if _, err := db.Exec(stmt); err != nil {
			slog.Error("DB create table", "error", err)
		}
	}

	// Ensure soar_config default row
	db.Exec(`INSERT IGNORE INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages) VALUES (1, TRUE, TRUE, TRUE, TRUE, TRUE)`)

	// Ensure the single backup_settings row (id=1) always exists so the worker can
	// read rotation config at runtime without a NULL-row special case.
	db.Exec(`INSERT IGNORE INTO backup_settings (id) VALUES (1)`)

	// Column migrations (idempotent — errors from "already exists" are ignored)
	migrations := []string{
		"ALTER TABLE users ADD COLUMN email VARCHAR(255) NOT NULL DEFAULT ''",
		"ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'Viewer'",
		"ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE users ADD COLUMN mfa_secret TEXT",
		"ALTER TABLE users ADD COLUMN github_url VARCHAR(500) NOT NULL DEFAULT ''",
		"ALTER TABLE ssh_keys ADD COLUMN associated_vms TEXT",
		"ALTER TABLE apps ADD COLUMN health_status VARCHAR(20) NOT NULL DEFAULT 'unknown'",
		"ALTER TABLE apps ADD COLUMN health_response_ms INT NOT NULL DEFAULT 0",
		"ALTER TABLE apps ADD COLUMN health_last_check DATETIME NULL",
		"ALTER TABLE apps ADD COLUMN is_pinned BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE apps ADD COLUMN position INT NOT NULL DEFAULT 0",
		"ALTER TABLE apps MODIFY COLUMN icon_url MEDIUMTEXT",
		"ALTER TABLE backup_runs ADD COLUMN upid VARCHAR(255) NOT NULL DEFAULT ''",
		"ALTER TABLE backup_runs ADD COLUMN destination VARCHAR(20) NOT NULL DEFAULT 'local'",
		"ALTER TABLE backup_runs ADD COLUMN remote VARCHAR(64) NOT NULL DEFAULT ''",
		"ALTER TABLE backup_runs ADD COLUMN push_status VARCHAR(20) NOT NULL DEFAULT ''",
		// Vérification automatique d'intégrité après chaque sauvegarde cloud (N1).
		"ALTER TABLE backup_settings ADD COLUMN auto_verify_enabled BOOLEAN NOT NULL DEFAULT FALSE",
		// Ansible scheduler hardening (Lot C — non-root). These are ADDITIVE/SAFE and
		// idempotent: they NEVER drop the column or rewrite existing rows.
		//   - become: opt-in privilege escalation (sudo) for non-root remote users.
		//     Defaults to FALSE so existing rows keep their current behaviour.
		//   - remote_user DROP DEFAULT: kills the unsafe DEFAULT 'root' (root SSH is
		//     disabled everywhere — PermitRootLogin=no — so a new schedule must never
		//     silently fall back to 'root'). MySQL 8 syntax: ALTER COLUMN ... DROP
		//     DEFAULT. The column stays NOT NULL: the application now REQUIRES an
		//     explicit remote_user at creation, so no INSERT relies on the default.
		//     Existing 'root' rows are LEFT UNTOUCHED on purpose (see the WARN below).
		//   - ADD remote_user (idempotent): a PRE-jalon prod table can pre-date this
		//     column (it only ever lived in CREATE TABLE, never as an ALTER), so the
		//     scheduler hit "Unknown column 'remote_user'". Add it BEFORE dropping its
		//     default; a Duplicate-column error (fresh install where CREATE already made
		//     it) is ignored by the loop. Legacy rows get '' and are flagged at run time
		//     (remote_user required) instead of crashing.
		"ALTER TABLE ansible_schedules ADD COLUMN remote_user VARCHAR(50) NOT NULL DEFAULT ''",
		"ALTER TABLE ansible_schedules ADD COLUMN become BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE ansible_schedules ALTER COLUMN remote_user DROP DEFAULT",
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			if !strings.Contains(err.Error(), "Duplicate column") && !strings.Contains(err.Error(), "exists") {
				slog.Info("DB migration (may already exist)", "sql", m, "error", err)
			}
		}
	}

	// Warn (non-fatal) if any existing schedule still targets the 'root' SSH user:
	// with PermitRootLogin=no on the fleet, those schedules fail UNREACHABLE. We do
	// NOT rewrite them blindly (no safe nominative user to pick) — the operator must
	// edit them to a non-root user, optionally enabling become (sudo) for escalation.
	var rootSchedules int
	if err := db.QueryRow("SELECT COUNT(*) FROM ansible_schedules WHERE remote_user = 'root'").Scan(&rootSchedules); err == nil && rootSchedules > 0 {
		slog.Warn("Ansible schedules still target the 'root' SSH user; these will fail if root SSH login is disabled (PermitRootLogin=no) — recreate them with a non-root user and enable 'become' for sudo escalation",
			"count", rootSchedules)
	}
}
