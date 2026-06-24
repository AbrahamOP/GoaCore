package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"goacloud/deploy/goabackup"
)

// TestBuildInstallerScript_EmbedsHelperVerbatimWithMatchingSHA is the integrity
// contract: the script inlines the EMBEDDED helper byte-for-byte AND publishes the
// sha256 of that exact embed, so the on-host `sha256sum` check the script runs can
// never reject a faithful install nor accept a tampered one.
func TestBuildInstallerScript_EmbedsHelperVerbatimWithMatchingSHA(t *testing.T) {
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyDataHere goabackup-channel@goacloud"
	script := buildInstallerScript(pub, "dash.example.test:8443")

	// The published EXPECTED_SHA256 must equal the sha256 of the embedded helper.
	sum := sha256.Sum256([]byte(goabackup.Runner))
	want := hex.EncodeToString(sum[:])
	if !strings.Contains(script, `readonly EXPECTED_SHA256="`+want+`"`) {
		t.Errorf("installer does not publish the embedded helper sha256 %s", want)
	}

	// The helper body must appear verbatim inside the quoted heredoc so the on-disk
	// file hashes to EXPECTED_SHA256. Spot-check a distinctive readonly const.
	if !strings.Contains(script, "readonly VMID_SANDBOX_MIN=9500") {
		t.Error("installer does not inline the helper body verbatim (sandbox const missing)")
	}

	// The heredoc must be QUOTED ('GOABACKUP_RUNNER_EOF') so bash performs zero
	// expansion on the helper body — otherwise the on-disk bytes (and the hash) drift.
	if !strings.Contains(script, "<<'GOABACKUP_RUNNER_EOF'") {
		t.Error("helper heredoc is not quoted — bash would expand the body and break the sha256")
	}
}

// TestBuildInstallerScript_PubkeyInjectedAndForcedCommand verifies the authorized_keys
// line is built with the forced-command + restrictions and the CURRENT public key.
func TestBuildInstallerScript_PubkeyInjectedAndForcedCommand(t *testing.T) {
	const pub = "ssh-ed25519 AAAAExampleKeyDataHere comment"
	script := buildInstallerScript(pub, "host:8443")

	if !strings.Contains(script, `readonly PUBKEY="`+pub+`"`) {
		t.Error("public key not injected verbatim into PUBKEY")
	}
	// The forced-command + no-pty restrictions must be present in the authorized_keys
	// assembly (without them the channel would not be locked to the read-only helper).
	for _, frag := range []string{
		`command=\"sudo $HELPER_PATH\"`,
		"no-port-forwarding",
		"no-pty",
	} {
		if !strings.Contains(script, frag) {
			t.Errorf("installer missing authorized_keys restriction %q", frag)
		}
	}
}

// TestBuildInstallerScript_CollapsesMultilinePubkey is the injection guard: a malformed
// pubkey carrying a newline must NOT be able to add a second authorized_keys line. Only
// the first line survives into PUBKEY.
func TestBuildInstallerScript_CollapsesMultilinePubkey(t *testing.T) {
	const evil = "ssh-ed25519 AAAAlegit comment\nssh-ed25519 AAAAattacker injected"
	script := buildInstallerScript(evil, "host")

	if strings.Contains(script, "AAAAattacker") {
		t.Error("multiline pubkey leaked a second key line into the installer (injection)")
	}
	if !strings.Contains(script, `readonly PUBKEY="ssh-ed25519 AAAAlegit comment"`) {
		t.Error("the legitimate first pubkey line was not preserved")
	}
}

// TestBuildInstallerScript_IsIdempotentAndSafe spot-checks the idempotency + safety
// invariants the design mandates: getent-guarded useradd with /bin/bash, visudo -cf
// before installing sudoers, and the disk-free self-test.
func TestBuildInstallerScript_IsIdempotentAndSafe(t *testing.T) {
	script := buildInstallerScript("ssh-ed25519 AAAA x", "host")
	for _, frag := range []string{
		"getent passwd \"$GOABACKUP_USER\"", // idempotent user check
		"-s /bin/bash",                      // real login shell (forced-command needs it)
		"visudo -cf",                        // sudoers validated before install
		"SSH_ORIGINAL_COMMAND='disk-free'",  // end-to-end self-test
		"set -euo pipefail",                 // strict mode
	} {
		if !strings.Contains(script, frag) {
			t.Errorf("installer missing required safety fragment %q", frag)
		}
	}
}

// TestHostFromURL strips the scheme, path and API port so the channel target is the
// bare host (the channel itself appends the SSH :22).
func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"https://192.168.40.20:8006":      "192.168.40.20",
		"https://192.168.40.20:8006/api2": "192.168.40.20",
		"http://pve.local:8006":           "pve.local",
		"https://10.0.0.1":                "10.0.0.1",
		"":                                "",
		"https://host:8006/?x=1":          "host",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Errorf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSanitizeForEcho keeps only host/port-safe characters so a weird r.Host can never
// break the shell comment block it is echoed into.
func TestSanitizeForEcho(t *testing.T) {
	if got := sanitizeForEcho("dash.example.com:8443"); got != "dash.example.com:8443" {
		t.Errorf("clean host mangled: %q", got)
	}
	if got := sanitizeForEcho("evil`whoami`$(id);rm"); got != "evilwhoamiidrm" {
		t.Errorf("sanitizeForEcho left shell metachars: %q", got)
	}
}

// TestChannelRootCommand stays in AUDITABLE mode (download → less → run), never a blind
// curl|sudo bash, and carries -k for the self-signed cert.
func TestChannelRootCommand(t *testing.T) {
	cmd := channelRootCommand("https://host:8443/api/onboarding/canal/installer.sh")
	if !strings.Contains(cmd, "less ") {
		t.Error("root command should download+inspect (less) before running")
	}
	if !strings.Contains(cmd, "curl -k") {
		t.Error("root command must use -k for the self-signed cert")
	}
	if strings.Contains(cmd, "curl -k -fsSL https://host:8443/api/onboarding/canal/installer.sh | sudo bash") {
		t.Error("root command must NOT be a blind curl|sudo bash pipe")
	}
}
