package config

import (
	"os"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "all empty is valid (optional services)",
			cfg:  Config{},
		},
		{
			name: "valid https urls",
			cfg: Config{
				ProxmoxURL:      "https://192.0.2.20:8006",
				WazuhAPIURL:     "https://192.0.2.30:55000",
				WazuhIndexerURL: "https://192.0.2.30:9200",
				AIURL:           "http://192.0.2.10:11434",
			},
		},
		{
			name:    "missing scheme on a blocking URL (Wazuh) is fatal",
			cfg:     Config{WazuhAPIURL: "192.0.2.30:55000"},
			wantErr: true,
		},
		{
			name:    "missing host",
			cfg:     Config{WazuhAPIURL: "https://"},
			wantErr: true,
		},
		{
			name:    "garbage url",
			cfg:     Config{AIURL: "ht!tp://%zz"},
			wantErr: true,
		},
		{
			// Since Jalon 1 a malformed PROXMOX_URL from the env is NOT fatal: the
			// connection can be (re)configured in-app, so Validate must not block boot.
			name: "malformed PROXMOX_URL is no longer fatal",
			cfg:  Config{ProxmoxURL: "192.0.2.20:8006"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRequireForBoot(t *testing.T) {
	// A config that mirrors what production injects: DB creds present + a strong
	// 53-char SESSION_SECRET. This MUST pass (the prod-boot guarantee).
	good := Config{
		DBUser:        "goacloud",
		DBPass:        "a-strong-db-password",
		DBName:        "goacloud",
		SessionSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123", // 53 chars
	}
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr bool
	}{
		{name: "prod-like config boots", mutate: func(c *Config) {}},
		{name: "missing DB_USER", mutate: func(c *Config) { c.DBUser = "" }, wantErr: true},
		{name: "missing DB_PASS", mutate: func(c *Config) { c.DBPass = "" }, wantErr: true},
		{name: "missing DB_NAME", mutate: func(c *Config) { c.DBName = "" }, wantErr: true},
		{name: "empty SESSION_SECRET", mutate: func(c *Config) { c.SessionSecret = "" }, wantErr: true},
		{name: "placeholder SESSION_SECRET", mutate: func(c *Config) { c.SessionSecret = "super-secret-key-change-me" }, wantErr: true},
		{name: "short SESSION_SECRET", mutate: func(c *Config) { c.SessionSecret = "tooshort" }, wantErr: true},
		{
			// Optional services absent must NOT block boot (vierge-instance guarantee).
			name:   "no optional services is fine",
			mutate: func(c *Config) { c.ProxmoxURL, c.WazuhAPIURL, c.AIProvider, c.DiscordBotToken = "", "", "", "" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := good // copy
			tt.mutate(&cfg)
			err := cfg.RequireForBoot()
			if (err != nil) != tt.wantErr {
				t.Errorf("RequireForBoot() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestLoadAIProviderDefaultEmpty pins the AI_PROVIDER default to "" so a vierge
// instance does not instantiate an Ollama client at localhost:11434.
func TestLoadAIProviderDefaultEmpty(t *testing.T) {
	t.Setenv("AI_PROVIDER", "")
	// Setenv sets the var to empty (present-but-empty); ensure Load reads it as empty.
	if got := Load().AIProvider; got != "" {
		t.Errorf("AIProvider default = %q, want empty", got)
	}
}

// TestLoadDBCredentialsNoDefault pins DB_USER/DB_PASS to no insecure default.
func TestLoadDBCredentialsNoDefault(t *testing.T) {
	for _, key := range []string{"DB_USER", "DB_PASS"} {
		os.Unsetenv(key)
	}
	cfg := Load()
	if cfg.DBUser != "" {
		t.Errorf("DBUser default = %q, want empty (no root fallback)", cfg.DBUser)
	}
	if cfg.DBPass != "" {
		t.Errorf("DBPass default = %q, want empty (no root fallback)", cfg.DBPass)
	}
}

func TestValidateURL(t *testing.T) {
	good := []string{"https://192.0.2.20:8006", "http://host", "https://h:9200/path"}
	bad := []string{"192.0.2.20:8006", "https://", "ht!tp://%zz", ""}
	for _, u := range good {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", u)
		}
	}
}

func TestProxmoxURLWarning(t *testing.T) {
	if w := (&Config{}).ProxmoxURLWarning(); w != "" {
		t.Errorf("empty PROXMOX_URL should not warn, got %q", w)
	}
	if w := (&Config{ProxmoxURL: "https://192.0.2.20:8006"}).ProxmoxURLWarning(); w != "" {
		t.Errorf("valid PROXMOX_URL should not warn, got %q", w)
	}
	if w := (&Config{ProxmoxURL: "192.0.2.20:8006"}).ProxmoxURLWarning(); w == "" {
		t.Error("malformed PROXMOX_URL should warn, got empty")
	}
}
