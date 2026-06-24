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
	// Registry holds the LIVE service clients (Wazuh API, Wazuh Indexer, AI, Discord)
	// and hot-reloads them in place on in-app onboarding — the client-snapshot sibling
	// of ConfigStore. Handlers and workers that read a hot-reloadable client MUST go
	// through Registry.Wazuh()/Indexer()/AI()/Discord() per request/tick (lock-free).
	// All four services are now fully migrated to the registry — there is no boot-time
	// client field left on the Handler.
	Registry *services.ServiceRegistry
	// ChannelRegistry holds the LIVE read-only Proxmox helper channel (goabackup) and
	// hot-reloads it in place when an admin provisions or rotates the in-app ed25519 key
	// — the channel sibling of Registry. The onboarding-canal handlers read it via
	// ChannelRegistry.Channel() (lock-free) for the live "Vérifier l'installation"
	// disk-free probe, and write through ApplyChannel/RollbackToEnv on provision/delete.
	ChannelRegistry *services.ChannelRegistry
}
