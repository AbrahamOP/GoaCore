package workers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/services"
)

// StartProxmoxAuthMonitor starts the background worker that monitors Proxmox
// authentication events.
//
// The "is Proxmox configured?" check lives INSIDE the ticker loop (not at entry):
// on a fresh instance with no Proxmox yet, the worker must NOT exit permanently —
// it idles tick after tick and self-activates the moment an admin onboards Proxmox
// in-app (hot-reload), exactly like the cache worker. Credentials are read live via
// store.ProxmoxSnapshot() on every tick (lock-free, always coherent).
func StartProxmoxAuthMonitor(ctx context.Context, store *config.ConfigStore, proxmox *services.ProxmoxService, discord *services.DiscordBot) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	slog.Info("Starting Proxmox Auth Monitor...")

	// lastN < 0 means "not yet primed": the first tick that finds Proxmox configured
	// seeds it from the current syslog tail so we don't replay history as alerts.
	lastN := -1

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("Proxmox Auth Monitor stopped")
			return
		case <-ticker.C:
			pm := store.ProxmoxSnapshot()
			switch proxmoxTickAction(pm, lastN) {
			case tickIdle:
				// Not configured yet — idle and re-check next tick (survives a
				// from-scratch boot and reactivates automatically on hot-reload).
				continue
			case tickPrime:
				// First time we see a configured Proxmox: prime the cursor without
				// emitting alerts for pre-existing log lines.
				lastN = proxmoxSyslogGetLastN(pm, proxmox)
			case tickCheck:
				lastN = checkProxmoxAuthEvents(pm, proxmox, discord, lastN)
			}
		}
	}
}

// proxmoxTickAction is the pure decision the auth-monitor ticker makes each tick,
// extracted so it can be unit-tested without a live Proxmox. It encodes the
// self-activation contract (BLOQUANT #3): an unconfigured snapshot ALWAYS idles
// (never a permanent exit), the first configured tick primes, and every tick
// after that checks. lastN < 0 means "not yet primed".
//
// "Configured" uses the SAME criterion as the onboarding gate (URL + token id +
// token secret, via ProxmoxConn.Configured()) so the worker never wakes up on a
// half-filled connection the gate considers unconfigured (a URL+TokenID without the
// secret would otherwise leak past here and hammer the API with a guaranteed 401).
func proxmoxTickAction(pm config.ProxmoxConn, lastN int) tickAction {
	if !pm.Configured() {
		return tickIdle
	}
	if lastN < 0 {
		return tickPrime
	}
	return tickCheck
}

// tickAction is the outcome of proxmoxTickAction.
type tickAction int

const (
	tickIdle  tickAction = iota // Proxmox not configured: idle, re-check next tick
	tickPrime                   // configured for the first time: seed the cursor
	tickCheck                   // configured and primed: scan for new auth events
)

func proxmoxSyslogGetLastN(pm config.ProxmoxConn, proxmox *services.ProxmoxService) int {
	entries := proxmox.FetchSyslog(pm.URL, pm.Node, pm.TokenID, pm.TokenSecret, 0, 500)
	maxN := 0
	for _, e := range entries {
		if e.N > maxN {
			maxN = e.N
		}
	}
	return maxN
}

func checkProxmoxAuthEvents(pm config.ProxmoxConn, proxmox *services.ProxmoxService, discord *services.DiscordBot, lastN int) int {
	entries := proxmox.FetchSyslog(pm.URL, pm.Node, pm.TokenID, pm.TokenSecret, lastN, 200)

	for _, entry := range entries {
		if entry.N <= lastN {
			continue
		}
		lastN = entry.N
		line := entry.T

		if !strings.Contains(line, "pvedaemon") {
			continue
		}

		if discord == nil || !discord.IsReady() {
			continue
		}

		if strings.Contains(line, "successful auth for user") {
			user := proxmoxExtractUser(line)
			go discord.SendAuthAlert(
				"✅ Connexion Proxmox réussie",
				fmt.Sprintf("**Utilisateur :** %s\n**Serveur :** %s\n**Log :** `%s`", user, pm.URL, line),
				false,
			)
		} else if strings.Contains(line, "authentication failure") || strings.Contains(line, "failed auth") {
			user := proxmoxExtractUser(line)
			go discord.SendAuthAlert(
				"❌ Échec de connexion Proxmox",
				fmt.Sprintf("**Utilisateur :** %s\n**Serveur :** %s\n**Log :** `%s`", user, pm.URL, line),
				false,
			)
		}
	}

	return lastN
}

func proxmoxExtractUser(line string) string {
	for _, prefix := range []string{"for user '", "for user "} {
		if idx := strings.Index(line, prefix); idx != -1 {
			rest := line[idx+len(prefix):]
			rest = strings.TrimPrefix(rest, "'")
			if end := strings.IndexAny(rest, "' \t"); end != -1 {
				return rest[:end]
			}
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return "inconnu"
}
