package workers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/models"
	"goacloud/internal/services"
	"goacloud/internal/sse"
)

// StartCacheWorker starts the background worker that updates the VM IP cache and Proxmox stats cache.
// Proxmox credentials are read live from the ConfigStore on every tick (Snapshot),
// so an in-app re-onboarding takes effect on the next cycle without a restart.
func StartCacheWorker(ctx context.Context, db *sql.DB, store *config.ConfigStore, proxmox *services.ProxmoxService, cache *models.ProxmoxCache, broker *sse.Broker) {
	slog.Info("Starting VM Cache Worker...")
	updateVMCache(db, store, proxmox, cache, broker)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Cache Worker stopped")
			return
		case <-ticker.C:
			updateVMCache(db, store, proxmox, cache, broker)
		}
	}
}

func updateVMCache(db *sql.DB, store *config.ConfigStore, proxmox *services.ProxmoxService, cache *models.ProxmoxCache, broker *sse.Broker) {
	// Lock-free, always-coherent read of the live Proxmox connection. Re-read each
	// tick so a hot-reload is picked up on the next cycle.
	pm := store.ProxmoxSnapshot()
	if !pm.Configured() {
		slog.Info("Worker: Missing Proxmox configuration")
		return
	}

	slog.Info("Worker: Updating VM IP cache...")
	stats, err := proxmox.GetStats(pm.URL, pm.Node, pm.TokenID, pm.TokenSecret, true, true)
	if err != nil {
		slog.Error("Worker Error", "error", err)
		return
	}

	// Update in-memory Proxmox stats cache (used by /proxmox page)
	cache.Mutex.Lock()
	cache.Stats = stats
	cache.UpdatedAt = time.Now()
	cache.Mutex.Unlock()

	// Persist IPs to DB
	for _, vm := range stats.VMs {
		if _, err := db.Exec(`
			INSERT INTO vm_cache (vmid, name, ip_address, vm_type)
			VALUES (?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address), name = VALUES(name), updated_at = NOW()`,
			vm.ID, vm.Name, vm.IP, vm.Type); err != nil {
			slog.Error("Worker DB Error", "vmid", vm.ID, "error", err)
		}
	}
	// Record metrics for history/sparklines
	if _, err := db.Exec("INSERT INTO metrics_history (cpu, ram, storage) VALUES (?, ?, ?)", stats.CPU, stats.RAM, stats.Storage); err != nil {
		slog.Error("Worker: failed to insert metrics", "error", err)
	}
	// Prune old entries (keep last 7 days)
	if _, err := db.Exec("DELETE FROM metrics_history WHERE recorded_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"); err != nil {
		slog.Error("Worker: failed to prune old metrics", "error", err)
	}

	// Broadcast to SSE clients
	if broker != nil {
		if data, err := json.Marshal(stats); err == nil {
			broker.Publish(data)
		}
	}

	slog.Info("Worker: VM cache updated", "count", len(stats.VMs))
}

// RefreshVMCache runs a single VM-cache update synchronously, out of band from the
// ticker. The onboarding handler calls it right after a successful Proxmox Save so
// the VM list / stats are populated immediately, without waiting for the next tick.
// It is safe to call concurrently with the worker (all writes are DB upserts and a
// mutex-guarded cache).
func RefreshVMCache(db *sql.DB, store *config.ConfigStore, proxmox *services.ProxmoxService, cache *models.ProxmoxCache, broker *sse.Broker) {
	updateVMCache(db, store, proxmox, cache, broker)
}
