package handlers

import (
	"database/sql"
	"html/template"
	"sync"

	"github.com/gorilla/sessions"
	"goacloud/internal/config"
	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/services"
	"goacloud/internal/sse"
)

// Handler holds all handler dependencies (replaces global variables).
type Handler struct {
	DB           *sql.DB
	Templates    *template.Template
	SessionStore *sessions.CookieStore
	WazuhClient  *services.WazuhClient
	WazuhIndexer *services.WazuhIndexerClient
	AIClient     services.AIClient
	Discord      *services.DiscordBot
	Config       *config.Config
	WazuhCache   *models.WazuhCache
	ProxmoxCache *models.ProxmoxCache
	VulnCache    *sync.Map
	SoarConfig   *models.SoarConfigState
	RateLimiter  *middleware.RateLimiter
	SSHService   *services.SSHService
	Proxmox      *services.ProxmoxService
	Backup       *services.BackupService
	SSEBroker    *sse.Broker
	// ConfigStore is the live, concurrency-safe source of the Proxmox connection.
	// Onboarding writes through ConfigStore.ApplyProxmox (hot-reload). Request
	// handlers MUST read the Proxmox connection via ConfigStore.ProxmoxSnapshot()
	// (lock-free, always coherent) — never via Config.Proxmox*, which is seeded once
	// at boot and would be a data race against a hot-reload.
	ConfigStore *config.ConfigStore
	// Connections persists per-service infrastructure credentials (Proxmox at
	// Jalon 1) configured in-app, with the secret encrypted at rest.
	Connections *services.ConnectionStore
}
