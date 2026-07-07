package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"goacore/internal/middleware"
	"goacore/internal/models"
)

// OverviewData is the home page ("single pane of glass") model. Everything here
// is read from in-memory caches or the local DB, so the page renders instantly;
// the one live/slow source (backups → Proxmox) is fetched separately and
// asynchronously by the browser via HandleOverviewBackups.
type OverviewData struct {
	Username string
	IsAdmin  bool

	// Services (app health checks)
	AppsUp    int
	AppsDown  int
	AppsTotal int

	// Infrastructure (Proxmox cache)
	ProxmoxConfigured bool
	CPU               int
	RAM               int
	Storage           int
	RAMUsedStr        string
	RAMTotalStr       string
	VMsRunning        int
	VMsStopped        int

	// Security (Wazuh)
	WazuhConfigured   bool
	WazuhActive       int
	WazuhDisconnected int
	Alerts24h         int
	Alerts24hKnown    bool // false when the indexer is not configured

	// Pinned apps → quick-access shortcuts
	Favorites []models.App

	// Derived global health: OK / Dégradé / Critique
	InfraHealth string
	// HealthIssues lists the concrete reasons behind a Dégradé/Critique state
	// (e.g. "CPU à 92%", "1 application hors ligne"). Empty when everything is OK.
	HealthIssues []string
}

func (h *Handler) HandleOverview(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	isAdmin := middleware.GetSessionRole(r, h.SessionStore) == "Admin"

	// --- Apps health + favorites ---
	apps, err := h.getApps()
	if err != nil {
		slog.Error("Overview: getApps error", "error", err)
		apps = []models.App{}
	}
	up, down := 0, 0
	var favorites []models.App
	for _, a := range apps {
		switch a.HealthStatus {
		case "up":
			up++
		case "down":
			down++
		}
		if a.IsPinned {
			favorites = append(favorites, a)
		}
	}

	// --- Proxmox (cache, instant) ---
	h.ProxmoxCache.Mutex.RLock()
	stats := h.ProxmoxCache.Stats
	h.ProxmoxCache.Mutex.RUnlock()
	running, stopped := 0, 0
	for _, vm := range stats.VMs {
		if vm.Status == "running" {
			running++
		} else {
			stopped++
		}
	}
	proxmoxConfigured := len(stats.VMs) > 0 || stats.CPU > 0 || stats.RAM > 0

	// --- Wazuh (cache, instant) ---
	var active, offline, crit, high int
	wazuhConfigured := false
	if h.WazuhCache != nil {
		h.WazuhCache.Mutex.RLock()
		agents := append([]models.WazuhAgent(nil), h.WazuhCache.Agents...)
		h.WazuhCache.Mutex.RUnlock()
		wazuhConfigured = len(agents) > 0
		for _, a := range agents {
			if a.Status == "active" {
				active++
			} else {
				offline++
			}
			crit += a.VulnSummary.Critical
			high += a.VulnSummary.High
		}
	}

	// --- Recent alerts (24h) — indexer is live but fast; nil when unconfigured ---
	alerts24h, alertsKnown := 0, false
	if idx := h.Registry.Indexer(); idx != nil {
		if list, err := idx.GetRecentAlerts(24 * time.Hour); err == nil {
			alerts24h, alertsKnown = len(list), true
		} else {
			slog.Warn("Overview: GetRecentAlerts failed", "error", err)
		}
	}

	// --- Derived global health + concrete reasons ---
	health := "OK"
	if stats.CPU >= 90 || stats.RAM >= 90 || stats.Storage >= 90 || down > 0 || crit > 0 {
		health = "Critique"
	} else if stats.CPU >= 75 || stats.RAM >= 75 || stats.Storage >= 75 || high > 0 || offline > 0 {
		health = "Dégradé"
	}
	var issues []string
	if stats.CPU >= 75 {
		issues = append(issues, fmt.Sprintf("CPU à %d%%", stats.CPU))
	}
	if stats.RAM >= 75 {
		issues = append(issues, fmt.Sprintf("RAM à %d%%", stats.RAM))
	}
	if stats.Storage >= 75 {
		issues = append(issues, fmt.Sprintf("Stockage à %d%%", stats.Storage))
	}
	if down > 0 {
		issues = append(issues, fmt.Sprintf("%d application(s) hors ligne", down))
	}
	if offline > 0 {
		issues = append(issues, fmt.Sprintf("%d agent(s) Wazuh déconnecté(s)", offline))
	}
	if crit > 0 {
		issues = append(issues, fmt.Sprintf("%d vulnérabilité(s) critique(s)", crit))
	}
	if high > 0 {
		issues = append(issues, fmt.Sprintf("%d vulnérabilité(s) haute(s)", high))
	}

	data := OverviewData{
		Username: username,
		IsAdmin:  isAdmin,

		AppsUp:    up,
		AppsDown:  down,
		AppsTotal: len(apps),

		ProxmoxConfigured: proxmoxConfigured,
		CPU:               stats.CPU,
		RAM:               stats.RAM,
		Storage:           stats.Storage,
		RAMUsedStr:        stats.RAMUsedStr,
		RAMTotalStr:       stats.RAMTotalStr,
		VMsRunning:        running,
		VMsStopped:        stopped,

		WazuhConfigured:   wazuhConfigured,
		WazuhActive:       active,
		WazuhDisconnected: offline,
		Alerts24h:         alerts24h,
		Alerts24hKnown:    alertsKnown,

		Favorites:    favorites,
		InfraHealth:  health,
		HealthIssues: issues,
	}

	if err := h.Templates.ExecuteTemplate(w, "overview.html", data); err != nil {
		slog.Error("Overview template error", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}

// HandleOverviewBackups returns the backup coverage summary as JSON. It is loaded
// asynchronously by the Overview page because BackupService.Dashboard() makes a
// live Proxmox call (slow) — keeping it off the initial render path so the home
// stays instant. Soft-fails to {configured:false} when backups aren't set up.
func (h *Handler) HandleOverviewBackups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	out := map[string]interface{}{"configured": false}

	if h.Backup != nil {
		if _, summary, err := h.Backup.Dashboard(); err == nil && summary.Total > 0 {
			out = map[string]interface{}{
				"configured": true,
				"total":      summary.Total,
				"ok":         summary.OK,
				"atRisk":     summary.AtRisk,
				"coverage":   summary.CoveragePct,
			}
		} else if err != nil {
			slog.Warn("Overview backups: Dashboard failed", "error", err)
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}
