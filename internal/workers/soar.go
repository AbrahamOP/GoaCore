package workers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"goacloud/internal/models"
	"goacloud/internal/services"
)

// ollamaSemaphore caps concurrent calls to the AI backend.
//
// Why a semaphore: when N alerts arrive in one polling tick, the previous
// implementation launched N goroutines that each hit Ollama in parallel. On a
// CPU-only inference host this saturates and every request hits its
// `context deadline exceeded`. We cap to 2 concurrent inferences — enough to
// keep latency hidden behind the Discord round-trip, low enough to never
// overload the model.
//
// Adjust via env SOAR_AI_MAX_PARALLEL (default 2).
var ollamaSemaphore chan struct{}

// soarMinLevel filters Indexer alerts below this Wazuh level out of the
// enrichment+notify pipeline. Curated rule.ids in
// `wazuhIndexer.GetRecentAlertsWithMinLevel` still pass regardless of level
// (auth/FIM/sudo/packages are interesting even at low level).
//
// Configured via env SOAR_MIN_LEVEL (default 10).
var soarMinLevel int = 10

func init() {
	maxPar := 2
	if v := os.Getenv("SOAR_AI_MAX_PARALLEL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxPar = n
		}
	}
	ollamaSemaphore = make(chan struct{}, maxPar)

	if v := os.Getenv("SOAR_MIN_LEVEL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			soarMinLevel = n
		}
	}
}

// StartSoarWorker starts the background worker that checks SOAR events and sends alerts.
func StartSoarWorker(
	ctx context.Context,
	db *sql.DB,
	wazuhClient *services.WazuhClient,
	wazuhIndexer *services.WazuhIndexerClient,
	aiClient services.AIClient,
	discord *services.DiscordBot,
	soarConfig *models.SoarConfigState,
) {
	slog.Info("Starting SOAR Worker...")

	loadSoarConfig(db, soarConfig)

	agentStatus := &sync.Map{}
	alertDedup := &sync.Map{}

	// Populate initial state without alerting
	if wazuhClient != nil {
		agents, err := wazuhClient.GetAgents()
		if err == nil {
			for _, agent := range agents {
				agentStatus.Store(agent.ID, agent.Status)
			}
			slog.Info("SOAR Init: Loaded state", "agents", len(agents))
		}
	}

	// Start dedup cleaner
	go StartAlertDedupCleaner(ctx, alertDedup)

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	slog.Info("SOAR Worker config", "ai_max_parallel", cap(ollamaSemaphore), "min_level", soarMinLevel)

	tickCount := 0
	for {
		select {
		case <-ctx.Done():
			slog.Info("SOAR Worker stopped")
			return
		case <-ticker.C:
			tickCount++
			// Heartbeat every 5 ticks (= 5 minutes) so a silent worker
			// is visible in `docker logs goacloud_app | grep heartbeat`.
			// History: 2026-04-29 incident — worker died silently for
			// 5 days, no one noticed because Discord just stopped firing.
			if tickCount%5 == 0 {
				slog.Info("SOAR Worker heartbeat", "ticks", tickCount, "running_for_min", tickCount)
			}
			loadSoarConfig(db, soarConfig)
			checkSoarEvents(wazuhClient, wazuhIndexer, aiClient, discord, soarConfig, agentStatus, alertDedup)
		}
	}
}

// StartAlertDedupCleaner periodically removes old alert dedup entries to prevent memory leaks.
func StartAlertDedupCleaner(ctx context.Context, alertDedup *sync.Map) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * time.Hour)
			alertDedup.Range(func(k, v interface{}) bool {
				if t, ok := v.(time.Time); ok && t.Before(cutoff) {
					alertDedup.Delete(k)
				}
				return true
			})
		}
	}
}

func loadSoarConfig(db *sql.DB, state *models.SoarConfigState) {
	state.Mutex.Lock()
	defer state.Mutex.Unlock()

	row := db.QueryRow("SELECT alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages FROM soar_config WHERE id = 1")
	err := row.Scan(
		&state.Config.AlertStatus,
		&state.Config.AlertSSH,
		&state.Config.AlertSudo,
		&state.Config.AlertFIM,
		&state.Config.AlertPackages,
	)
	if err != nil {
		slog.Error("Error loading SOAR config from DB, using defaults", "error", err)
		state.Config = models.SoarConfig{AlertStatus: true, AlertSSH: true, AlertSudo: true, AlertFIM: true, AlertPackages: true}
	}
}

func checkSoarEvents(
	wazuhClient *services.WazuhClient,
	wazuhIndexer *services.WazuhIndexerClient,
	aiClient services.AIClient,
	discord *services.DiscordBot,
	soarConfig *models.SoarConfigState,
	agentStatus *sync.Map,
	alertDedup *sync.Map,
) {
	if wazuhClient == nil {
		return
	}

	soarConfig.Mutex.RLock()
	cfg := soarConfig.Config
	soarConfig.Mutex.RUnlock()

	// 1. Check for Status Changes
	if cfg.AlertStatus {
		agents, err := wazuhClient.GetAgents()
		if err != nil {
			slog.Error("SOAR Worker Error (GetAgents)", "error", err)
		} else {
			for _, agent := range agents {
				prevStatusInterface, loaded := agentStatus.Load(agent.ID)
				agentStatus.Store(agent.ID, agent.Status)

				if loaded {
					prevStatus := prevStatusInterface.(string)
					if prevStatus != agent.Status {
						slog.Info("SOAR State Change", "agent", agent.Name, "from", prevStatus, "to", agent.Status)

						if agent.Status == "disconnected" {
							ctx := services.AIAlertContext{
								Title:       "🔴 Agent Perdu",
								Description: fmt.Sprintf("L'agent **%s** ne répond plus.", agent.Name),
								AgentName:   agent.Name,
								AgentIP:     agent.IP,
								RuleLevel:   10,
							}
							go sendEnrichedAlert(ctx, "critical", aiClient, discord)
						} else if agent.Status == "active" && prevStatus == "disconnected" {
							ctx := services.AIAlertContext{
								Title:       "🟢 Agent Retrouvé",
								Description: fmt.Sprintf("L'agent **%s** est de nouveau en ligne.", agent.Name),
								AgentName:   agent.Name,
								AgentIP:     agent.IP,
								RuleLevel:   0,
							}
							go sendEnrichedAlert(ctx, "info", aiClient, discord)
						}
					}
				}
			}
		}
	}

	// 2. Check for Indexer Alerts
	if wazuhIndexer != nil {
		alerts, err := wazuhIndexer.GetRecentAlertsWithMinLevel(2*time.Minute, soarMinLevel)
		if err != nil {
			slog.Error("SOAR Worker Error (Indexer)", "error", err)
		} else {
			for _, alert := range alerts {
				alertKey := alert.Agent.ID + alert.Rule.ID + alert.Timestamp
				if _, loaded := alertDedup.Load(alertKey); !loaded {
					alertDedup.Store(alertKey, time.Now())

					title, msg, severity, shouldSend := classifyAlert(alert, cfg)
					if !shouldSend {
						continue
					}

					aiCtx := services.AIAlertContext{
						Title:           title,
						Description:     msg,
						AgentName:       alert.Agent.Name,
						AgentIP:         alert.Agent.IP,
						RuleID:          alert.Rule.ID,
						RuleLevel:       alert.Rule.Level,
						RuleGroups:      alert.Rule.Groups,
						MitreIDs:        alert.Rule.MITRE.ID,
						MitreTactics:    alert.Rule.MITRE.Tactic,
						MitreTechniques: alert.Rule.MITRE.Technique,
						FullLog:         alert.FullLog,
						SourceIP:        alert.Data.SrcIP,
					}
					go sendEnrichedAlert(aiCtx, severity, aiClient, discord)
				}
			}
		}
	}
}

// classifyAlert turns a raw Wazuh alert into a Discord-ready (title, message,
// severity) tuple. Returns shouldSend=false when the SoarConfig disables the
// relevant category. Centralised so the noisy switch lives in one place.
func classifyAlert(alert services.WazuhAlert, cfg models.SoarConfig) (title, msg, severity string, shouldSend bool) {
	switch alert.Rule.ID {

	// --- Correlation rules (Phase 3 — 2026-05-21) ---------------------
	case "100500":
		// SSH brute force probably successful (multiple failures then success
		// same IP). Always critical: if the worker noticed this, a real
		// attacker has a shell.
		return "🚨 Brute Force SSH RÉUSSI",
			fmt.Sprintf("**Machine:** %s\n**Source IP:** %s\n**Détail:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Data.SrcIP, alert.Rule.Description, alert.FullLog),
			"critical", true

	case "100510":
		// 3+ attack-tagged alerts from same source in 30min. Strong active
		// attack signal — keep critical.
		return "⚔️ Attaque multi-étapes en cours",
			fmt.Sprintf("**Machine cible:** %s\n**Source IP:** %s\n**Pattern:** %s",
				alert.Agent.Name, alert.Data.SrcIP, alert.Rule.Description),
			"critical", true

	// --- Claude Code audit (Phase 2) ---------------------------------
	case "100302":
		return "🧹 Claude Code: rm en rafale",
			fmt.Sprintf("**Machine:** %s\n**Détail:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Rule.Description, alert.FullLog),
			"high", true
	case "100303":
		return "🔑 Claude Code: accès fichier sensible",
			fmt.Sprintf("**Machine:** %s\n**Détail:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Rule.Description, alert.FullLog),
			"critical", true
	case "100304":
		return "⚠️ Claude Code: exec depuis /tmp ou /dev/shm",
			fmt.Sprintf("**Machine:** %s\n**Détail:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Rule.Description, alert.FullLog),
			"critical", true
	case "100305":
		return "🛑 Claude Code: tool call bloqué",
			fmt.Sprintf("**Machine:** %s\n**Détail:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Rule.Description, alert.FullLog),
			"medium", true

	// --- Suricata HIGH ----------------------------------------------
	case "100202":
		return "🦠 Suricata HIGH",
			fmt.Sprintf("**Machine:** %s\n**Source IP:** %s\n**Signature:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Data.SrcIP, alert.Rule.Description, alert.FullLog),
			"critical", true

	// --- Existing categories ----------------------------------------
	case "5402":
		if !cfg.AlertSudo {
			return "", "", "", false
		}
		return "👑 Élévation de Privilèges",
			fmt.Sprintf("**Machine:** %s\n**Event:** Sudo to ROOT\n**Log:** `%s`",
				alert.Agent.Name, alert.FullLog),
			"critical", true
	case "550", "553", "554":
		if !cfg.AlertFIM {
			return "", "", "", false
		}
		return "📝 Intégrité des Fichiers",
			fmt.Sprintf("**Machine:** %s\n**Fichier:** `%s`\n**Event:** %s",
				alert.Agent.Name, alert.Syscheck.Path, alert.Rule.Description),
			"high", true
	case "2902", "2903":
		if !cfg.AlertPackages {
			return "", "", "", false
		}
		return "📦 Gestion Logicielle",
			fmt.Sprintf("**Machine:** %s\n**Changement:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Rule.Description, alert.FullLog),
			"info", true
	}

	// --- Generic high-level fallback (rule.level >= soarMinLevel and
	// not matched above). Caught because we added the `range
	// rule.level >= minLevel` clause in GetRecentAlertsWithMinLevel.
	if alert.Rule.Level >= 10 {
		sev := "high"
		if alert.Rule.Level >= 12 {
			sev = "critical"
		}
		return fmt.Sprintf("🛡️ Alerte Wazuh niveau %d", alert.Rule.Level),
			fmt.Sprintf("**Machine:** %s\n**Règle %s:** %s\n**Source IP:** %s\n**Log:** `%s`",
				alert.Agent.Name, alert.Rule.ID, alert.Rule.Description, alert.Data.SrcIP, alert.FullLog),
			sev, true
	}

	// SSH/auth catch-all (5710/5712/5716/5503 etc.) — only if alert.ssh enabled.
	if cfg.AlertSSH {
		sev := "medium"
		if alert.Rule.ID == "5712" {
			sev = "high"
		}
		return "🛡️ Alerte Sécurité",
			fmt.Sprintf("**Machine:** %s\n**Event:** %s\n**Source IP:** %s",
				alert.Agent.Name, alert.Rule.Description, alert.Data.SrcIP),
			sev, true
	}

	return "", "", "", false
}

func sendEnrichedAlert(alertCtx services.AIAlertContext, severity string, aiClient services.AIClient, discord *services.DiscordBot) {
	if discord == nil || !discord.IsReady() {
		return
	}

	msg := alertCtx.Description

	if aiClient != nil {
		// Bounded concurrency: never more than cap(ollamaSemaphore) Ollama
		// calls in flight. Without this, parallel goroutines saturate the
		// CPU-only Ollama box and every call ends in "context deadline
		// exceeded" — observed live on 2026-04-29.
		ollamaSemaphore <- struct{}{}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		analysis, err := aiClient.EnrichAlert(ctx, alertCtx)
		cancel()
		<-ollamaSemaphore
		if err == nil {
			msg += fmt.Sprintf("\n\n🤖 **Analyse AI:**\n%s", analysis)
		} else {
			slog.Error("AI Enrichment Failed", "error", err, "rule_id", alertCtx.RuleID)
		}
	}

	if err := discord.SendAlert(alertCtx.Title, msg, severity); err != nil {
		slog.Error("Discord SendAlert failed", "error", err, "rule_id", alertCtx.RuleID)
	}
}
