package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/sessions"
	"goacloud/assets"
	"goacloud/internal/config"
	"goacloud/internal/database"
	"goacloud/internal/handlers"
	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/router"
	"goacloud/internal/server"
	"goacloud/internal/services"
	"goacloud/internal/sse"
	"goacloud/internal/workers"
)

func main() {
	// Structured JSON logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Load config
	cfg := config.Load()

	if cfg.SkipTLSVerify {
		slog.Warn("SKIP_TLS_VERIFY=true — TLS certificate verification disabled")
	}
	if cfg.SessionSecret == "super-secret-key-change-me" {
		slog.Error("SESSION_SECRET is the default value — refusing to start. Set a strong secret via SESSION_SECRET env var.")
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("Invalid configuration — refusing to start", "error", err)
		os.Exit(1)
	}
	// PROXMOX_URL is no longer fatal (it can be configured/fixed in-app). Surface a
	// malformed env value as a Warn so a typo is visible without blocking the boot.
	if w := cfg.ProxmoxURLWarning(); w != "" {
		slog.Warn(w)
	}

	// Database
	db, err := database.Connect(cfg)
	if err != nil {
		slog.Error("Cannot connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("Connected to MySQL database")

	database.Migrate(db)

	// Templates
	funcMap := template.FuncMap{
		"json": func(v interface{}) (template.JS, error) {
			a, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			// Escape </script> and <!-- to prevent injection in <script> blocks
			s := strings.ReplaceAll(string(a), "</", `<\/`)
			s = strings.ReplaceAll(s, "<!--", `<\!--`)
			return template.JS(s), nil
		},
	}
	tmpl := template.New("").Funcs(funcMap)
	if _, statErr := os.Stat("assets/templates"); statErr == nil {
		slog.Info("Loading templates from disk (Development Mode)")
		tmpl, err = tmpl.ParseGlob("assets/templates/*.html")
	} else {
		slog.Info("Loading embedded templates (Production Mode)")
		tmpl, err = tmpl.ParseFS(assets.TemplatesFS, "templates/*.html")
	}
	if err != nil {
		slog.Error("Error parsing templates", "error", err)
		os.Exit(1)
	}

	// Services
	proxmoxService := services.NewProxmoxService(db, cfg.SkipTLSVerify)

	// SSH service first: it is the AES-256-GCM crypto engine (key derived from
	// SESSION_SECRET) reused to encrypt/decrypt the in-app Proxmox token, and it
	// carries the Proxmox creds for the root console — which ConfigStore refreshes
	// on a hot-reload via SetProxmoxCreds. It MUST exist before the ConfigStore and
	// the ConnectionStore, and before ReloadProxmox (which decrypts the DB secret).
	sshEncKey := handlers.DeriveSSHEncKey(cfg.SessionSecret)
	sshService := services.NewSSHService(
		db, sshEncKey,
		cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret,
		cfg.SkipTLSVerify,
	)
	sshService.MigrateEncryptSSHKeys()

	// Connection store (DB persistence of in-app infra creds) + ConfigStore (live,
	// concurrency-safe Proxmox connection, atomic.Pointer swap on reload).
	connStore := services.NewConnectionStore(db, sshService)
	configStore := config.NewConfigStore(cfg, sshService)

	// Resolve the effective Proxmox connection: DB row wins over env when present
	// and enabled; otherwise the env values already in cfg are the fallback. This
	// is tolerant by design — a missing/undecipherable row never aborts the boot.
	reloadProxmoxFromDB(connStore, configStore)

	backupService := services.NewBackupService(db, proxmoxService, configStore)

	// Wire the read-only Proxmox helper channel for restore testing (nil-safe:
	// the feature degrades to clear errors if GOABACKUP_SSH_* are unset).
	restoreChannel := services.NewProxmoxChannel(cfg)
	backupService.SetChannel(restoreChannel)
	if restoreChannel.Configured() {
		slog.Info("Restore-test channel configured", "host", cfg.GoabackupSSHHost, "user", cfg.GoabackupSSHUser)
	} else {
		slog.Info("Restore-test channel not configured (missing GOABACKUP_SSH_HOST/KEY_FILE)")
	}

	// Reconcile zombie backup runs left "running" by a previous restart: their
	// driving goroutine is gone, so they would otherwise stay stuck forever.
	if n, err := backupService.ReconcileRunningRuns(); err != nil {
		slog.Error("backup: reconcile running runs", "error", err)
	} else if n > 0 {
		slog.Info("backup: reconciled orphaned running runs", "count", n)
	}

	// Same reconciliation for orphaned restore tests (DB rows).
	if n, err := backupService.ReconcileRunningTests(); err != nil {
		slog.Error("restore-test: reconcile running tests", "error", err)
	} else if n > 0 {
		slog.Info("restore-test: reconciled orphaned running tests", "count", n)
	}

	var wazuhClient *services.WazuhClient
	if cfg.WazuhAPIURL != "" {
		slog.Info("Configuring Wazuh Client", "url", cfg.WazuhAPIURL)
		wazuhClient = services.NewWazuhClient(cfg.WazuhAPIURL, cfg.WazuhUser, cfg.WazuhPassword, cfg.SkipTLSVerify)
	} else {
		slog.Info("Wazuh URL not configured")
	}

	var wazuhIndexer *services.WazuhIndexerClient
	if cfg.WazuhIndexerURL != "" {
		slog.Info("Configuring Wazuh Indexer Client", "url", cfg.WazuhIndexerURL)
		wazuhIndexer = services.NewWazuhIndexerClient(cfg.WazuhIndexerURL, cfg.WazuhIndexerUser, cfg.WazuhIndexerPass, cfg.SkipTLSVerify)
	}

	var aiClient services.AIClient
	if cfg.AIURL != "" || cfg.AIAPIKey != "" || cfg.AIProvider == "ollama" {
		aiClient = services.NewAIClient(cfg.AIProvider, cfg.AIURL, cfg.AIAPIKey, cfg.AIModel, cfg.OpenAIBaseURL)
		if aiClient != nil {
			slog.Info("AI Client configured", "provider", cfg.AIProvider, "model", cfg.AIModel)
		}
	} else {
		slog.Info("AI enrichment disabled (missing configuration)")
	}

	// Session store
	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 1,
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	}

	// Discord
	var discordBot *services.DiscordBot
	if cfg.DiscordBotToken != "" && cfg.DiscordChannelID != "" {
		bot, botErr := services.NewDiscordBot(cfg.DiscordBotToken, cfg.DiscordChannelID, cfg.DiscordAuthChannel, cfg.DiscordAnsibleChannel)
		if botErr != nil {
			slog.Error("Failed to init Discord Bot", "error", botErr)
		} else {
			discordBot = bot
			defer discordBot.Close()
		}
	} else {
		slog.Info("Discord Bot not configured (missing token or channel)")
	}

	// Wire Discord notifications into the backup service (nil-safe).
	backupService.SetDiscord(discordBot)

	// Purge any guest leaked in the disposable sandbox range [9500,9599] on the
	// host (a crash mid-test can leave one behind). No legitimate guest ever lives
	// there — the whole range is disposable by definition. Done AFTER the DB
	// reconciliation above and AFTER Discord is wired so zombie alerts can fire.
	if restoreChannel.Configured() {
		if n, err := backupService.ReconcileSandboxGuests(); err != nil {
			slog.Error("restore-test: reconcile sandbox guests", "error", err)
		} else if n > 0 {
			slog.Warn("restore-test: purged leaked sandbox guests at boot", "count", n)
		}
	}

	// Shared state
	wazuhCache := &models.WazuhCache{}
	proxmoxCache := &models.ProxmoxCache{}
	vulnCache := &sync.Map{}
	soarConfigState := &models.SoarConfigState{}
	soarConfigState.Config = models.SoarConfig{
		AlertStatus:   true,
		AlertSSH:      true,
		AlertSudo:     true,
		AlertFIM:      true,
		AlertPackages: true,
	}

	// SSE broker
	sseBroker := sse.NewBroker()

	// Rate limiter
	rateLimiter := middleware.NewRateLimiter()

	// Handler
	h := &handlers.Handler{
		DB:           db,
		Templates:    tmpl,
		SessionStore: store,
		WazuhClient:  wazuhClient,
		WazuhIndexer: wazuhIndexer,
		AIClient:     aiClient,
		Discord:      discordBot,
		Config:       cfg,
		WazuhCache:   wazuhCache,
		ProxmoxCache: proxmoxCache,
		VulnCache:    vulnCache,
		SoarConfig:   soarConfigState,
		RateLimiter:  rateLimiter,
		SSHService:   sshService,
		Proxmox:      proxmoxService,
		Backup:       backupService,
		SSEBroker:    sseBroker,
		ConfigStore:  configStore,
		Connections:  connStore,
	}

	// Background workers with context for graceful shutdown
	workerCtx, workerCancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	startWorker := func(name string, fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(workerCtx)
		}()
	}

	startWorker("cache", func(ctx context.Context) {
		workers.StartCacheWorker(ctx, db, configStore, proxmoxService, proxmoxCache, sseBroker)
	})
	startWorker("wazuh", func(ctx context.Context) {
		workers.StartWazuhWorker(ctx, wazuhClient, wazuhIndexer, wazuhCache, vulnCache)
	})
	startWorker("soar", func(ctx context.Context) {
		workers.StartSoarWorker(ctx, db, wazuhClient, wazuhIndexer, aiClient, discordBot, soarConfigState)
	})
	startWorker("proxmox-auth", func(ctx context.Context) {
		workers.StartProxmoxAuthMonitor(ctx, configStore, proxmoxService, discordBot)
	})
	startWorker("health", func(ctx context.Context) {
		workers.StartHealthWorker(ctx, db)
	})
	startWorker("ansible", func(ctx context.Context) {
		workers.StartAnsibleScheduler(ctx, db, sshService, discordBot)
	})
	startWorker("backup-test-scheduler", func(ctx context.Context) {
		// Rotation enablement/hour are read live from the DB (backup_settings) by
		// the worker; the GOABACKUP_TEST_* env vars no longer drive it.
		workers.StartBackupTestScheduler(ctx, backupService, discordBot)
	})

	// TLS cert
	if err := server.EnsureCert(); err != nil {
		slog.Error("Error generating TLS certificate", "error", err)
		os.Exit(1)
	}

	// Router
	appRouter := router.New(h, store, db, cfg.CookieSecure)

	// Start server
	srv := server.New(cfg.HTTPPort, cfg.HTTPSPort, appRouter)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTPS server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("Shutting down server...")

	// Stop all background workers
	workerCancel()
	workerDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workerDone)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	// Wait for workers to finish (with timeout)
	select {
	case <-workerDone:
		slog.Info("All workers stopped")
	case <-ctx.Done():
		slog.Warn("Timeout waiting for workers to stop")
	}

	slog.Info("Server stopped gracefully")
}

// reloadProxmoxFromDB resolves the effective Proxmox connection at boot with the
// precedence DB(enabled row) > env > defaults, and publishes it through the
// ConfigStore (atomic swap + SSH creds refresh). It is intentionally tolerant:
//
//   - no DB row            → keep the env values already loaded in cfg (fallback),
//   - row present+enabled  → DB values WIN (override env),
//   - undecipherable secret → log + fall back to env, never abort the boot.
//
// The effective source is logged once so ops can tell where the live config came
// from (DB / env / unconfigured).
func reloadProxmoxFromDB(connStore *services.ConnectionStore, configStore *config.ConfigStore) {
	conn, secret, err := connStore.GetProxmox()
	if err != nil {
		// Most likely an undecipherable secret (SESSION_SECRET changed). Record the
		// errored status, do NOT override the env fallback, and keep booting.
		slog.Warn("Proxmox connection in DB could not be loaded — falling back to env", "error", err)
		if serr := connStore.SetStatus("proxmox", "error", "secret indéchiffrable (SESSION_SECRET modifié ?)"); serr != nil {
			slog.Warn("Proxmox: set connection status failed", "error", serr)
		}
		logProxmoxSource(configStore, "env")
		return
	}
	if conn == nil || !conn.Enabled {
		// No DB override: env (already in cfg) is the source of truth.
		logProxmoxSource(configStore, "env")
		return
	}
	storage, bridge := services.ProxmoxExtra(conn)
	configStore.ApplyProxmox(config.ProxmoxConn{
		URL:         conn.URL,
		Node:        conn.Node,
		TokenID:     conn.TokenID,
		TokenSecret: secret,
		Storage:     storage,
		Bridge:      bridge,
	})
	logProxmoxSource(configStore, "DB")
}

// logProxmoxSource logs the effective Proxmox configuration source once at boot.
func logProxmoxSource(configStore *config.ConfigStore, source string) {
	if configStore.ProxmoxConfigured() {
		slog.Info("Proxmox configuration resolved", "source", source)
	} else {
		slog.Info("Proxmox configuration resolved", "source", "unconfigured")
	}
}
