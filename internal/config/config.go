package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Database
	DBUser string
	DBPass string
	DBHost string
	DBName string

	// Proxmox
	ProxmoxURL         string
	ProxmoxNode        string
	ProxmoxTokenID     string
	ProxmoxTokenSecret string
	// Storage and bridge used when creating VMs/CTs. Empty = auto-detect via the
	// Proxmox API (first active storage supporting images/rootfs, first bridge).
	ProxmoxStorage string
	ProxmoxBridge  string

	// Wazuh API
	WazuhAPIURL   string
	WazuhUser     string
	WazuhPassword string

	// Wazuh Indexer
	WazuhIndexerURL  string
	WazuhIndexerUser string
	WazuhIndexerPass string

	// AI
	AIProvider string
	AIURL      string
	AIAPIKey   string
	AIModel    string
	// OpenAIBaseURL targets an OpenAI-compatible endpoint (self-hosted/sovereign).
	OpenAIBaseURL string

	// Discord
	DiscordBotToken       string
	DiscordChannelID      string
	DiscordAuthChannel    string
	DiscordAnsibleChannel string

	// GoaBackup restore-test channel (read-only SSH helper on the Proxmox host)
	GoabackupSSHHost    string
	GoabackupSSHUser    string
	GoabackupSSHKeyFile string

	// GoaBackup scheduled restore-test rotation
	BackupTestRotationEnabled bool
	BackupTestHour            int

	// Server
	HTTPPort      string
	HTTPSPort     string
	SessionSecret string
	CookieSecure  bool
	SkipTLSVerify bool
}

// Load reads configuration from environment variables with defaults.
func Load() *Config {
	cfg := &Config{
		// DB defaults are dev-only conveniences; production deployments inject
		// DB_USER/DB_PASS via the compose/env file (see docker-compose-dev.yml).
		DBUser:                getEnv("DB_USER", "root"),
		DBPass:                getEnv("DB_PASS", "root"),
		DBHost:                getEnv("DB_HOST", "127.0.0.1:3306"),
		DBName:                getEnv("DB_NAME", "goacloud"),
		ProxmoxURL:            getEnv("PROXMOX_URL", ""),
		ProxmoxNode:           getEnv("PROXMOX_NODE", "pve"),
		ProxmoxTokenID:        getEnv("PROXMOX_TOKEN_ID", ""),
		ProxmoxTokenSecret:    getEnv("PROXMOX_TOKEN_SECRET", ""),
		ProxmoxStorage:        getEnv("PROXMOX_STORAGE", ""),
		ProxmoxBridge:         getEnv("PROXMOX_BRIDGE", ""),
		WazuhAPIURL:           getEnv("WAZUH_API_URL", ""),
		WazuhUser:             getEnv("WAZUH_USER", ""),
		WazuhPassword:         getEnv("WAZUH_PASSWORD", ""),
		WazuhIndexerURL:       getEnv("WAZUH_INDEXER_URL", ""),
		WazuhIndexerUser:      getEnv("WAZUH_INDEXER_USER", ""),
		WazuhIndexerPass:      getEnv("WAZUH_INDEXER_PASSWORD", ""),
		AIProvider:            getEnv("AI_PROVIDER", "ollama"),
		AIURL:                 getEnv("AI_URL", ""),
		AIAPIKey:              getEnv("AI_API_KEY", ""),
		AIModel:               getEnv("AI_MODEL", ""),
		OpenAIBaseURL:         getEnv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
		DiscordBotToken:       getEnv("DISCORD_BOT_TOKEN", ""),
		DiscordChannelID:      getEnv("DISCORD_CHANNEL_ID", ""),
		DiscordAuthChannel:    getEnv("DISCORD_AUTH_CHANNEL_ID", ""),
		DiscordAnsibleChannel: getEnv("DISCORD_ANSIBLE_CHANNEL_ID", ""),
		GoabackupSSHHost:      getEnv("GOABACKUP_SSH_HOST", ""),
		GoabackupSSHUser:      getEnv("GOABACKUP_SSH_USER", "goabackup"),
		GoabackupSSHKeyFile:   getEnv("GOABACKUP_SSH_KEY_FILE", ""),

		BackupTestRotationEnabled: getEnvBool("GOABACKUP_TEST_ROTATION_ENABLED", false),
		BackupTestHour:            getEnvIntBounded("GOABACKUP_TEST_HOUR", 4, 0, 23),

		HTTPPort:      getEnv("PORT", "8080"),
		HTTPSPort:     getEnv("HTTPS_PORT", "8443"),
		SessionSecret: getEnv("SESSION_SECRET", "super-secret-key-change-me"),
		CookieSecure:  getEnv("COOKIE_SECURE", "true") != "false",
		SkipTLSVerify: getEnv("SKIP_TLS_VERIFY", "false") == "true",
	}

	// Legacy Ollama support
	if cfg.AIProvider == "ollama" && cfg.AIURL == "" {
		cfg.AIURL = getEnv("OLLAMA_URL", "")
	}
	if cfg.AIModel == "" {
		cfg.AIModel = getEnv("OLLAMA_MODEL", "")
	}

	return cfg
}

// Validate checks that configured service URLs are well-formed. Catching a
// malformed URL here (fail-fast at startup) avoids a nil-request panic later,
// deep inside a worker, when http.NewRequest is handed a bad URL derived from
// these values.
func (c *Config) Validate() error {
	for name, raw := range map[string]string{
		"PROXMOX_URL":       c.ProxmoxURL,
		"WAZUH_API_URL":     c.WazuhAPIURL,
		"WAZUH_INDEXER_URL": c.WazuhIndexerURL,
		"AI_URL":            c.AIURL,
	} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%s is not a valid absolute URL: %q", name, raw)
		}
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// getEnvBool reads a boolean env var. Accepts true/1/yes/on (case-insensitive).
func getEnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// getEnvIntBounded reads an int env var, clamping it to [min,max]. A missing or
// unparseable value yields the fallback (which is assumed already in range).
func getEnvIntBounded(key string, fallback, min, max int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}
