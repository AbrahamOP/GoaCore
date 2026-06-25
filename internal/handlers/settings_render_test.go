package handlers

import (
	"bytes"
	"encoding/json"
	"html/template"
	"strings"
	"testing"

	"goacore/internal/models"
)

// loadSettingsTemplates parses the on-disk template set exactly the way cmd/server
// boots it (same "json" FuncMap, same glob), so this test exercises the REAL parse +
// execute pipeline. The settings hub renders settings.html → {{template "settings-<section>"}}
// purely from the data map the handler builds; html/template only surfaces a missing
// define or a bad method/type call at EXECUTE time (build/vet stay green), so this is
// the one guard that catches a 500-on-render regression in any settings section.
func loadSettingsTemplates(t *testing.T) *template.Template {
	t.Helper()
	funcMap := template.FuncMap{
		"json": func(v interface{}) (template.JS, error) {
			a, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			s := strings.ReplaceAll(string(a), "</", `<\/`)
			s = strings.ReplaceAll(s, "<!--", `<\!--`)
			return template.JS(s), nil
		},
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseGlob("../../assets/templates/*.html")
	if err != nil {
		t.Fatalf("parsing templates failed: %v", err)
	}
	return tmpl
}

// settingsScaffold mirrors the keys settingsBase always sets, so each case only adds
// its section-specific keys on top — the same contract the handlers honour.
func settingsScaffold(section, subtitle string, admin bool) map[string]any {
	return map[string]any{
		"Section":        section,
		"Active":         section,
		"IsAdmin":        admin,
		"HeaderSubtitle": subtitle,
		"User":           "alice",
		"Error":          "",
		"Success":        "",
	}
}

// TestSettingsHubSectionsRender executes settings.html for every section of the
// Paramètres hub with a data map built like the matching handler. A panic or a
// non-nil ExecuteTemplate error means the section would 500 in production; an empty
// body means the section dispatch silently rendered nothing.
func TestSettingsHubSectionsRender(t *testing.T) {
	tmpl := loadSettingsTemplates(t)

	card := func(svc, source, status string) serviceCardData {
		return serviceCardData{
			Service: svc, Source: source, Status: status, Configured: true,
			SecretPresent: true, CanRollback: true, Wired: true,
			URL: "https://192.0.2.20:9200", User: "admin",
		}
	}

	cases := []struct {
		name    string
		data    map[string]any
		wantStr string // a marker that must appear once the section body rendered
	}{
		{
			name: "profil",
			data: func() map[string]any {
				d := settingsScaffold("profil", "Gérez vos informations personnelles.", false)
				d["Username"] = "alice"
				d["Email"] = "alice@example.com"
				d["Role"] = "Viewer"
				d["GithubURL"] = "https://github.com/alice"
				return d
			}(),
			wantStr: "alice@example.com",
		},
		{
			name: "securite",
			data: func() map[string]any {
				d := settingsScaffold("securite", "Protégez l'accès à votre compte.", false)
				d["MFAEnabled"] = false
				return d
			}(),
			wantStr: "Paramètres",
		},
		{
			name: "services",
			data: func() map[string]any {
				d := settingsScaffold("services", "Reliez GoaCore à vos services.", true)
				d["WazuhIndexer"] = card("wazuh-indexer", "db", "ok")
				d["Wazuh"] = card("wazuh", "env", "unknown")
				d["AI"] = card("ai", "unconfigured", "unknown")
				d["Discord"] = card("discord", "unconfigured", "unknown")
				d["Selected"] = "wazuh-indexer"
				return d
			}(),
			wantStr: "192.0.2.20",
		},
		{
			name: "utilisateurs",
			data: func() map[string]any {
				d := settingsScaffold("utilisateurs", "Gérez les comptes et les accès.", true)
				d["Users"] = []models.User{
					{ID: 1, Username: "alice", Email: "alice@example.com", Role: "Admin", CreatedAt: "2026-01-01"},
					{ID: 2, Username: "bob", Email: "bob@example.com", Role: "Viewer", CreatedAt: "2026-02-02"},
				}
				return d
			}(),
			wantStr: "bob@example.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, "settings.html", tc.data); err != nil {
				t.Fatalf("section %q failed to render: %v", tc.name, err)
			}
			out := buf.String()
			if len(out) == 0 {
				t.Fatalf("section %q rendered an empty body", tc.name)
			}
			if !strings.Contains(out, tc.wantStr) {
				t.Fatalf("section %q body missing expected marker %q (dispatch likely rendered the wrong/no section)", tc.name, tc.wantStr)
			}
		})
	}
}
