package workers

import (
	"testing"

	"goacore/internal/config"
)

// TestProxmoxTickAction covers the auth-monitor ticker decision (BLOQUANT #3): the
// check lives INSIDE the loop, so an unconfigured snapshot must idle (never a
// permanent exit) and the worker must self-activate the moment Proxmox is
// configured via hot-reload. lastN < 0 = not yet primed.
func TestProxmoxTickAction(t *testing.T) {
	configured := config.ProxmoxConn{URL: "https://pve:8006", TokenID: "id@pve!t", TokenSecret: "s"}
	tests := []struct {
		name  string
		pm    config.ProxmoxConn
		lastN int
		want  tickAction
	}{
		{"unconfigured (empty) idles, even if somehow primed", config.ProxmoxConn{}, 5, tickIdle},
		{"unconfigured (no URL) idles", config.ProxmoxConn{TokenID: "id"}, -1, tickIdle},
		{"unconfigured (no token) idles", config.ProxmoxConn{URL: "https://pve:8006"}, -1, tickIdle},
		// URL + TokenID but NO secret: the onboarding gate treats this as
		// unconfigured (Configured() needs all three), so the worker must idle too —
		// otherwise it would fire API calls doomed to 401 on a half-filled conn.
		{"URL+TokenID without secret idles (gate parity)", config.ProxmoxConn{URL: "https://pve:8006", TokenID: "id@pve!t"}, -1, tickIdle},
		{"first configured tick primes", configured, -1, tickPrime},
		{"configured + primed checks", configured, 42, tickCheck},
		{"configured + primed at zero checks", configured, 0, tickCheck},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxmoxTickAction(tt.pm, tt.lastN); got != tt.want {
				t.Errorf("proxmoxTickAction(%+v, %d) = %d, want %d", tt.pm, tt.lastN, got, tt.want)
			}
		})
	}
}

// TestProxmoxTickAction_ReactivatesAfterReload simulates the from-scratch →
// hot-reload sequence on the SAME store the worker reads: it idles while
// unconfigured, then primes (not idles) on the very first tick after an in-app
// ApplyProxmox, proving the worker resurrects itself without a restart.
func TestProxmoxTickAction_ReactivatesAfterReload(t *testing.T) {
	store := config.NewConfigStore(&config.Config{}, nil)
	lastN := -1

	// Fresh instance: several ticks while unconfigured must all idle (the worker
	// would otherwise have exited permanently before this lot's fix).
	for i := 0; i < 3; i++ {
		if got := proxmoxTickAction(store.ProxmoxSnapshot(), lastN); got != tickIdle {
			t.Fatalf("unconfigured tick %d = %d, want idle", i, got)
		}
	}

	// Admin onboards Proxmox in-app (hot-reload via the same store).
	store.ApplyProxmox(config.ProxmoxConn{URL: "https://pve:8006", TokenID: "id@pve!t", TokenSecret: "s"})

	// The next tick must prime (self-activation), then subsequent ticks check.
	if got := proxmoxTickAction(store.ProxmoxSnapshot(), lastN); got != tickPrime {
		t.Fatalf("first tick after reload = %d, want prime", got)
	}
	lastN = 7 // pretend prime seeded the cursor
	if got := proxmoxTickAction(store.ProxmoxSnapshot(), lastN); got != tickCheck {
		t.Fatalf("tick after prime = %d, want check", got)
	}
}

func TestProxmoxExtractUser(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "quoted user",
			line: "pvedaemon[1234]: successful auth for user 'root@pam'",
			want: "root@pam",
		},
		{
			name: "quoted user followed by text",
			line: "authentication failure; rhost=1.2.3.4 for user 'claude@pve' msg=bad",
			want: "claude@pve",
		},
		{
			name: "unquoted user terminated by space",
			line: "login attempt for user antoine from 10.0.0.5",
			want: "antoine",
		},
		{
			name: "user marker without the 'for user' prefix is ignored",
			line: "authentication failure for rhost=1.2.3.4 user 'bob@pam'",
			want: "inconnu",
		},
		{
			name: "no user marker",
			line: "pvedaemon: some unrelated log line",
			want: "inconnu",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxmoxExtractUser(tt.line); got != tt.want {
				t.Errorf("proxmoxExtractUser(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}
