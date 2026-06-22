package models

import "time"

// BackupTarget represents an entity (VM/LXC/app) managed and verified by GoaBackup.
type BackupTarget struct {
	ID                int
	Name              string
	TargetType        string // "qemu", "lxc", "app"
	SourceRef         string // VMID (e.g. "110") or path for app backups
	Storage           string // Proxmox storage holding the dumps (e.g. "local")
	Enabled           bool
	RPOHours          int    // freshness threshold (hours) before an RPO breach
	ScheduleCron      string // optional cron expression for backups (informational)
	RetentionCount    int    // number of backups to keep
	HealthcheckType   string // "none", "port", "service", "sql"
	HealthcheckTarget string // port / service name / SQL command, per HealthcheckType
	CreatedAt         time.Time
}

// BackupRun is a single execution of a backup job (vzdump or app dump).
type BackupRun struct {
	ID          int
	TargetID    int
	BackupType  string // "vzdump", "app"
	Status      string // "pending", "running", "completed", "failed"
	StartedAt   *time.Time
	CompletedAt *time.Time
	SizeBytes   int64
	ArchivePath string // local archive path
	Checksum    string
	Source      string // "manual", "scheduler", "external" (discovered)
	Message     string // error or info detail
	CreatedBy   string
	CreatedAt   time.Time
}

// RestoreTest is a single restore/verification run against a backup.
type RestoreTest struct {
	ID          int
	TargetID    int
	RunID       *int   // associated backup_run, if known
	Level       string // "N1" (integrity), "N2" (restore+boot), "N3" (+healthcheck)
	Verdict     string // "pending", "running", "passed", "failed"
	SandboxVMID int    // disposable VMID used (95xx); 0 for N1-only
	RTOSeconds  int    // measured restore-to-ready time
	StartedAt   *time.Time
	CompletedAt *time.Time
	Logs        string
	TriggeredBy string // "manual", "scheduler"
	CreatedAt   time.Time
}
