package handlers

import (
	"bytes"
	"strings"
	"testing"

	"goacore/internal/models"
)

// TestOverviewRenders executes overview.html end-to-end with a populated
// OverviewData, catching any missing field/method that only surfaces at execute
// time (parse alone stays green). Mirrors the settings render guard.
func TestOverviewRenders(t *testing.T) {
	tmpl := loadSettingsTemplates(t) // parses assets/templates/*.html incl. overview.html

	cases := map[string]OverviewData{
		"configured": {
			Username: "antoine", IsAdmin: true,
			AppsUp: 9, AppsDown: 1, AppsTotal: 11,
			ProxmoxConfigured: true, CPU: 42, RAM: 63, Storage: 55,
			RAMUsedStr: "20 Go", RAMTotalStr: "32 Go", VMsRunning: 12, VMsStopped: 3,
			WazuhConfigured: true, WazuhActive: 15, WazuhDisconnected: 1,
			Alerts24h: 4, Alerts24hKnown: true,
			InfraHealth:  "Dégradé",
			HealthIssues: []string{"CPU à 82%", "1 agent(s) Wazuh déconnecté(s)"},
			Favorites: []models.App{
				{Name: "Proxmox", ExternalURL: "https://proxmox.goacloud.fr", IconURL: "data:image/png;base64,AAA", HealthStatus: "up", IsPinned: true},
				{Name: "Wazuh", ExternalURL: "https://wazuh.goacloud.fr", HealthStatus: "down", IsPinned: true},
			},
		},
		"unconfigured": {
			Username: "antoine", InfraHealth: "OK", AppsTotal: 0,
		},
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, "overview.html", data); err != nil {
				t.Fatalf("overview render (%s) failed: %v", name, err)
			}
			out := buf.String()
			if !strings.Contains(out, `id="ov-health-text">`+data.InfraHealth) {
				t.Errorf("%s: health banner missing", name)
			}
		})
	}
}
