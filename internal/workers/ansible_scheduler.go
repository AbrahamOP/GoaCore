package workers

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"goacore/internal/services"
)

// StartAnsibleScheduler checks for due ansible schedules every 60 seconds and executes them.
//
// discord is a DiscordProvider (the registry): the live bot is re-resolved at the head
// of each tick (in runDueSchedules) and the resulting snapshot is handed to the async
// per-job goroutines. Because the executions run async, the bot MUST be re-read per
// tick — never captured at start — so an in-app Discord hot-reload reaches them.
func StartAnsibleScheduler(ctx context.Context, db *sql.DB, sshService *services.SSHService, discord services.DiscordProvider) {
	slog.Info("Starting Ansible Scheduler Worker...")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("Ansible Scheduler stopped")
			return
		case <-ticker.C:
			runDueSchedules(db, sshService, discord)
		}
	}
}

func runDueSchedules(db *sql.DB, sshService *services.SSHService, provider services.DiscordProvider) {
	// Snapshot the live bot once per tick; the async jobs below use this snapshot.
	var discord *services.DiscordBot
	if provider != nil {
		discord = provider.Discord()
	}
	rows, err := db.Query(`SELECT id, playbook, vmid, key_id, interval_minutes, remote_user, become
		FROM ansible_schedules WHERE enabled = TRUE AND next_run <= NOW()`)
	if err != nil {
		slog.Error("Ansible scheduler: DB error", "error", err)
		return
	}
	defer rows.Close()

	type job struct {
		ID              int
		Playbook        string
		VMID            int
		KeyID           int
		IntervalMinutes int
		RemoteUser      string
		Become          bool
	}

	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.ID, &j.Playbook, &j.VMID, &j.KeyID, &j.IntervalMinutes, &j.RemoteUser, &j.Become); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Ansible scheduler: row iteration error", "error", err)
	}

	for _, j := range jobs {
		go executeScheduledPlaybook(db, sshService, discord, j.ID, j.Playbook, j.VMID, j.KeyID, j.IntervalMinutes, j.RemoteUser, j.Become)
	}
}

func executeScheduledPlaybook(db *sql.DB, sshService *services.SSHService, discord *services.DiscordBot, scheduleID int, playbook string, vmid int, keyID int, intervalMinutes int, remoteUser string, become bool) {
	slog.Info("Ansible scheduler: executing", "schedule_id", scheduleID, "playbook", playbook, "vmid", vmid)

	// Guard legacy/invalid rows: root SSH is disabled fleet-wide (PermitRootLogin=no),
	// so a schedule still pinned to 'root' (or any invalid user) would fail UNREACHABLE
	// silently. Surface it as a clear error instead, prompting the admin to recreate the
	// schedule with a non-root user (+ become for escalation).
	if remoteUser == "root" {
		const msg = "remote_user 'root' is rejected: root SSH login is disabled (PermitRootLogin=no). Recreate this schedule with a non-root user and enable 'become' (sudo) for privilege escalation."
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", msg)
		notifyAnsibleExecution(discord, playbook, "?", vmid, "error", msg)
		return
	}
	if !services.ValidRemoteUser(remoteUser) {
		const msg = "invalid remote_user on schedule — recreate it with a valid non-root SSH user."
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", msg)
		notifyAnsibleExecution(discord, playbook, "?", vmid, "error", msg)
		return
	}

	// Get VM name for notifications
	var targetIP, vmName string
	err := db.QueryRow("SELECT ip_address, COALESCE(name,'?') FROM vm_cache WHERE vmid = ?", vmid).Scan(&targetIP, &vmName)
	if err != nil || targetIP == "" || targetIP == "-" {
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", "VM IP not found or not cached")
		notifyAnsibleExecution(discord, playbook, "?", vmid, "error", "VM IP not found or not cached")
		return
	}

	// Get SSH key
	sshKey, err := sshService.GetSSHKeyByID(keyID)
	if err != nil {
		msg := fmt.Sprintf("SSH key not found: %v", err)
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", msg)
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", msg)
		return
	}

	// Path traversal protection
	playbookPath := filepath.Join("playbooks", filepath.Clean(playbook))
	absPlaybooks, err1 := filepath.Abs("playbooks")
	absPath, err2 := filepath.Abs(playbookPath)
	if err1 != nil || err2 != nil || !strings.HasPrefix(absPath, absPlaybooks+string(filepath.Separator)) {
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", "Invalid playbook path")
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", "Invalid playbook path")
		return
	}

	// Run playbook
	cmdOut, cleanup, err := services.RunPlaybook(playbookPath, targetIP, sshKey.PrivateKey, remoteUser, become)
	if err != nil {
		msg := fmt.Sprintf("Execution error: %v", err)
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", msg)
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", msg)
		return
	}
	defer cleanup()

	// Read all output
	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, cmdOut)
	output := buf.String()

	// Statut basé d'abord sur le CODE DE SORTIE réel d'ansible-playbook (cleanup attend
	// la fin du process et le renvoie), puis sur les marqueurs de sortie en complément.
	// Un échec avec exit≠0 sans "fatal:"/"UNREACHABLE!" (erreur de syntaxe → "ERROR!",
	// process tué, etc.) n'est ainsi plus rapporté comme un succès. cleanup() est
	// idempotent : le defer ci-dessus reste le filet de sécurité (suppression de clé).
	exitErr := cleanup()
	status := "success"
	if copyErr != nil {
		status = "error"
		output += fmt.Sprintf("\n[scheduler] error reading playbook output: %v", copyErr)
	} else if exitErr != nil {
		status = "error"
		output += fmt.Sprintf("\n[scheduler] ansible-playbook a échoué (code de sortie) : %v", exitErr)
	} else if strings.Contains(output, "fatal:") || strings.Contains(output, "UNREACHABLE!") {
		status = "error"
	}

	// Truncate output if too long (keep last 4000 chars)
	if len(output) > 4000 {
		output = "...(truncated)\n" + output[len(output)-4000:]
	}

	updateScheduleResult(db, scheduleID, intervalMinutes, status, output)
	notifyAnsibleExecution(discord, playbook, vmName, vmid, status, output)
	slog.Info("Ansible scheduler: done", "schedule_id", scheduleID, "status", status)
}

func notifyAnsibleExecution(discord *services.DiscordBot, playbook, vmName string, vmid int, status, output string) {
	if discord == nil || !discord.IsReady() {
		return
	}
	if err := discord.SendAnsibleAlert(playbook, vmName, vmid, status, output); err != nil {
		slog.Error("Ansible scheduler: Discord notification failed", "error", err)
	}
}

func updateScheduleResult(db *sql.DB, scheduleID int, intervalMinutes int, status string, output string) {
	nextRun := time.Now().Add(time.Duration(intervalMinutes) * time.Minute)
	_, err := db.Exec(`UPDATE ansible_schedules
		SET last_run = NOW(), last_status = ?, last_output = ?, next_run = ?
		WHERE id = ?`, status, output, nextRun, scheduleID)
	if err != nil {
		slog.Error("Ansible scheduler: failed to update result", "error", err, "schedule_id", scheduleID)
	}
}
