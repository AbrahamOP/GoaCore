// Package goabackup embeds the canonical read-only helper script
// (goabackup-runner.sh) so it ships INSIDE the GoaCore binary.
//
// This embed is MANDATORY, not a convenience: the production Dockerfile copies
// only cmd/, internal/, assets/, playbooks/ and ansible.cfg into the build — it
// does NOT copy deploy/. Without //go:embed the helper simply would not exist in
// the alpine image, so the installer endpoint that serves it (and the anti-drift
// test that pins the sandbox VMID range against it) would have nothing to read.
//
// SOURCE OF TRUTH: this embedded copy is the single authority. The installer
// endpoint serves Runner verbatim (with a published SHA256 for integrity), and
// the anti-drift test parses the SAME bytes for VMID_SANDBOX_MIN/MAX — so what we
// SERVE and what the Go engine ENFORCES can never silently diverge.
package goabackup

import (
	_ "embed"
)

// Runner is the verbatim contents of goabackup-runner.sh, the read-only forced-command
// helper an admin installs on their Proxmox host. It is embedded so it travels in the
// binary (see package doc) and is the one copy the installer serves and the anti-drift
// test reads.
//
//go:embed goabackup-runner.sh
var Runner string
