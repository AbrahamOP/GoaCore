package services

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"goacore/deploy/goabackup"
	"goacore/internal/config"
)

// helperRunnerPath returns the path to the canonical goabackup helper script the Go
// engine and the bash autority must agree on. CI vendors it at deploy/goabackup/ in
// the repo; a GOABACKUP_RUNNER_PATH env override lets a developer point the test at
// a local development copy of goabackup-runner.sh during local work. The test
// SKIPS (not fails) when neither is present, so a checkout without the vendored copy
// still builds — but on CI the vendored file makes the drift guard mandatory.
func helperRunnerPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GOABACKUP_RUNNER_PATH"); p != "" {
		return p
	}
	// internal/services → repo root is two levels up.
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return filepath.Join(repoRoot, "deploy", "goabackup", "goabackup-runner.sh")
}

// TestSandboxVMIDRangeMatchesHelper is the anti-drift guard between the TWO sandbox
// VMID gates: the Go pre-filter (sandboxVMIDMin/Max) and the bash AUTHORITY
// (VMID_SANDBOX_MIN/MAX). They MUST stay identical — a silent divergence (Go thinks
// 9500-9599, bash widened the range) is worse than no guard, because it produces a
// false sense of safety while letting a destructive op reach a prod VMID.
//
// SOURCE OF TRUTH = the EMBED (goabackup.Runner), the EXACT bytes the installer
// endpoint serves and that travel in the binary (the Dockerfile does not copy
// deploy/). Parsing the embed — not a loose file — is what makes "what we serve"
// and "what Go enforces" provably identical. The build fails on any mismatch.
func TestSandboxVMIDRangeMatchesHelper(t *testing.T) {
	script := goabackup.Runner
	if script == "" {
		t.Fatal("embedded goabackup.Runner is empty (embed.go missing or //go:embed broken)")
	}

	min := parseHelperConst(t, script, "VMID_SANDBOX_MIN")
	max := parseHelperConst(t, script, "VMID_SANDBOX_MAX")

	if min != sandboxVMIDMin {
		t.Errorf("VMID_SANDBOX_MIN drift: embedded helper=%d Go=%d", min, sandboxVMIDMin)
	}
	if max != sandboxVMIDMax {
		t.Errorf("VMID_SANDBOX_MAX drift: embedded helper=%d Go=%d", max, sandboxVMIDMax)
	}
}

// TestEmbeddedHelperMatchesVendoredFile closes the only remaining gap: the embed is
// resolved at COMPILE time, so a stale binary could embed an old helper while the
// repo's vendored file (and the //go:embed directive's target) moved on. This asserts
// the embedded bytes equal the on-disk vendored copy byte-for-byte, so the embed can
// never silently lag the file the rest of the toolchain (and a reviewer) reads. It is
// SKIPPED — not failed — on a checkout without the vendored file or with an explicit
// GOABACKUP_RUNNER_PATH override pointing elsewhere, so the embed test above remains
// the mandatory guard while this one tightens the CI checkout where the file exists.
func TestEmbeddedHelperMatchesVendoredFile(t *testing.T) {
	if os.Getenv("GOABACKUP_RUNNER_PATH") != "" {
		t.Skip("GOABACKUP_RUNNER_PATH override set — skipping embed==vendored-file equality (the embed is the served authority)")
	}
	path := helperRunnerPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("helper not vendored at %s — embed is the authority, equality check skipped", path)
		}
		t.Fatalf("read vendored helper %s: %v", path, err)
	}
	if string(data) != goabackup.Runner {
		t.Errorf("embedded goabackup.Runner differs from vendored file %s — the served helper and the repo copy have drifted (rebuild or re-vendor)", path)
	}
}

// TestDiskInfo_HasThinPoolCeiling is the security gate against reading an absent/0
// thin_data_pct as "0% used ⇒ always pass": the ceiling guard must apply ONLY on a
// usable lvmthin reading, never on ZFS/dir/unknown/empty backends.
func TestDiskInfo_HasThinPoolCeiling(t *testing.T) {
	cases := []struct {
		name string
		d    DiskInfo
		want bool
	}{
		{"lvmthin with usage", DiskInfo{Backend: "lvmthin", ThinDataPct: 42}, true},
		{"lvmthin zero usage (no reading)", DiskInfo{Backend: "lvmthin", ThinDataPct: 0}, false},
		{"zfspool never ceilings", DiskInfo{Backend: "zfspool", ThinDataPct: 80}, false},
		{"dir never ceilings", DiskInfo{Backend: "dir"}, false},
		{"unknown never ceilings", DiskInfo{Backend: "unknown"}, false},
		{"empty backend (old helper) never ceilings", DiskInfo{Backend: "", ThinDataPct: 99}, false},
	}
	for _, tc := range cases {
		if got := tc.d.HasThinPoolCeiling(); got != tc.want {
			t.Errorf("%s: HasThinPoolCeiling() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestDiskInfo_IsBlindProbe is the fail-SAFE gate against a totally blind disk sonde
// authorising a destructive restore: when neither the thin-pool ceiling NOR a usable
// avail floor is present (df errored, or returned 0 on a non-lvmthin backend), the
// engine must REFUSE rather than fail-open. A usable ceiling OR a positive avail makes
// the probe non-blind.
func TestDiskInfo_IsBlindProbe(t *testing.T) {
	cases := []struct {
		name string
		d    DiskInfo
		want bool
	}{
		// df explicitly failed → 0 is a blind reading, not a real 0 → REFUSE.
		{"df failed, no ceiling", DiskInfo{Backend: "unknown", LocalAvailBytes: 0, AvailProbe: "failed"}, true},
		{"df failed on dir backend", DiskInfo{Backend: "dir", LocalAvailBytes: 0, AvailProbe: "failed"}, true},
		// No ceiling and a 0 avail even with avail_probe=ok (genuinely full / old helper
		// reporting 0) → still nothing guards → REFUSE.
		{"zero avail, no ceiling, probe ok", DiskInfo{Backend: "unknown", LocalAvailBytes: 0, AvailProbe: "ok"}, true},
		{"zero avail, empty probe (old helper)", DiskInfo{Backend: "", LocalAvailBytes: 0, AvailProbe: ""}, true},
		// A positive avail floor IS an effective guard → not blind.
		{"positive avail, no ceiling", DiskInfo{Backend: "dir", LocalAvailBytes: 5 << 30, AvailProbe: "ok"}, false},
		{"positive avail even if df flagged failed", DiskInfo{Backend: "dir", LocalAvailBytes: 5 << 30, AvailProbe: "failed"}, false},
		// A usable lvmthin ceiling IS an effective guard → not blind, even with df failed.
		{"thin ceiling present, df failed", DiskInfo{Backend: "lvmthin", ThinDataPct: 42, LocalAvailBytes: 0, AvailProbe: "failed"}, false},
		// lvmthin but 0% (no real reading) AND df failed → no ceiling, blind → REFUSE.
		{"lvmthin zero pct + df failed", DiskInfo{Backend: "lvmthin", ThinDataPct: 0, LocalAvailBytes: 0, AvailProbe: "failed"}, true},
	}
	for _, tc := range cases {
		if got := tc.d.IsBlindProbe(); got != tc.want {
			t.Errorf("%s: IsBlindProbe() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestSandboxPowerAction_RefusesNonSandboxVMID verifies the restore engine's guarded
// power wrapper refuses an out-of-range VMID BEFORE any Proxmox call (proxmox is nil
// here, so reaching PowerAction would panic — the refusal must happen first). This is
// the defense-in-depth that PowerAction itself does not carry (it is dual-use).
func TestSandboxPowerAction_RefusesNonSandboxVMID(t *testing.T) {
	s := newTestBackupService() // proxmox is nil
	pm := config.ProxmoxConn{URL: "https://pve:8006", TokenID: "t", TokenSecret: "x"}

	for _, vmid := range []int{0, 100, 110, 9499, 9600, 100000} {
		err := s.sandboxPowerAction(pm, "qemu", vmid, "start")
		if err == nil {
			t.Errorf("sandboxPowerAction(vmid=%d) returned nil, want a sandbox-range refusal", vmid)
		}
	}
}

// parseHelperConst extracts `readonly NAME=<int>` from the helper, failing the test
// if the line is missing or non-numeric (a guard so a renamed/removed const trips
// the build rather than silently passing).
func parseHelperConst(t *testing.T, script, name string) int {
	t.Helper()
	// Match e.g. `readonly VMID_SANDBOX_MIN=9500` (optionally without `readonly`).
	re := regexp.MustCompile(`(?m)^\s*(?:readonly\s+)?` + regexp.QuoteMeta(name) + `=(\d+)\b`)
	m := re.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("helper constant %q not found (renamed or removed?)", name)
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("helper constant %q not numeric: %q", name, m[1])
	}
	return v
}
