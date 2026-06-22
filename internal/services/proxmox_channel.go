package services

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"goacloud/internal/config"

	gossh "golang.org/x/crypto/ssh"
)

// ProxmoxChannel is the client for the read-only "goabackup" helper that runs on
// the Proxmox host. The helper is exposed over SSH with a forced-command: the
// string we send via session.Output(op) becomes the operation, and the helper
// replies with a single line of JSON. We never run arbitrary shell here — the
// host side decides what each op maps to.
//
// HostKeyCallback: we use InsecureIgnoreHostKey on purpose. The channel targets a
// fixed internal Proxmox host over the management VLAN with a pinned key file we
// control; there is no TOFU store wired for this service, and a failed host-key
// check would silently degrade the (optional) restore-test feature. The risk
// surface (internal-only, key-auth, read-only forced command) is acceptable.
type ProxmoxChannel struct {
	host    string
	user    string
	keyFile string
}

// NewProxmoxChannel builds a channel client from config. It is always safe to
// build (no I/O here); operations fail with a clear error if the channel is not
// configured (missing host/key), so the restore-test feature degrades gracefully.
func NewProxmoxChannel(cfg *config.Config) *ProxmoxChannel {
	if cfg == nil {
		return &ProxmoxChannel{}
	}
	host := cfg.GoabackupSSHHost
	if host != "" && !strings.Contains(host, ":") {
		host += ":22"
	}
	return &ProxmoxChannel{
		host:    host,
		user:    cfg.GoabackupSSHUser,
		keyFile: cfg.GoabackupSSHKeyFile,
	}
}

// Configured reports whether the channel has the minimum settings to operate.
func (c *ProxmoxChannel) Configured() bool {
	return c != nil && c.host != "" && c.keyFile != ""
}

// run sends a single operation over a fresh SSH session and returns the raw
// stdout (expected to be one line of JSON). It is nil-safe and never panics.
func (c *ProxmoxChannel) run(op string, timeout time.Duration) (string, error) {
	if c == nil {
		return "", fmt.Errorf("proxmox channel: not configured")
	}
	if c.host == "" || c.keyFile == "" {
		return "", fmt.Errorf("proxmox channel: not configured (missing host or key file)")
	}

	keyBytes, err := os.ReadFile(c.keyFile)
	if err != nil {
		return "", fmt.Errorf("proxmox channel: read key %s: %w", c.keyFile, err)
	}
	signer, err := gossh.ParsePrivateKey(keyBytes)
	if err != nil {
		return "", fmt.Errorf("proxmox channel: parse private key: %w", err)
	}

	// HostKeyCallback: InsecureIgnoreHostKey by design and documented on the
	// ProxmoxChannel type — a fixed internal Proxmox host over the management VLAN,
	// key-based auth, restricted to a read-only forced command. No TOFU store is
	// wired for this optional feature.
	hostKeyCB := gossh.InsecureIgnoreHostKey() //nolint:gosec // internal host, pinned key, read-only forced command

	user := c.user
	if user == "" {
		user = "goabackup"
	}

	clientCfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCB,
		Timeout:         15 * time.Second,
	}

	client, err := gossh.Dial("tcp", c.host, clientCfg)
	if err != nil {
		return "", fmt.Errorf("proxmox channel: dial %s: %w", c.host, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("proxmox channel: new session: %w", err)
	}
	defer session.Close()

	// Enforce the per-operation timeout: if Output overruns, close the session
	// to unblock and surface a timeout error.
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, runErr := session.Output(op)
		done <- result{out: out, err: runErr}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			return "", fmt.Errorf("proxmox channel: op %q failed: %w", op, res.err)
		}
		return strings.TrimSpace(string(res.out)), nil
	case <-time.After(timeout):
		_ = session.Close()
		return "", fmt.Errorf("proxmox channel: op %q timed out after %s", op, timeout)
	}
}

// channelEnvelope is the common shell of every helper response.
type channelEnvelope struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// DiskFree returns the thin pool data usage percentage and the local available
// bytes, used as a pre-flight guard before a destructive restore.
func (c *ProxmoxChannel) DiskFree() (thinDataPct float64, localAvailBytes int64, err error) {
	raw, err := c.run("disk-free", 30*time.Second)
	if err != nil {
		return 0, 0, err
	}
	var resp struct {
		channelEnvelope
		ThinDataPct     float64 `json:"thin_data_pct"`
		ThinMetaPct     float64 `json:"thin_meta_pct"`
		LocalAvailBytes int64   `json:"local_avail_bytes"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return 0, 0, fmt.Errorf("proxmox channel: decode disk-free %q: %w", raw, jerr)
	}
	if !resp.OK {
		return 0, 0, fmt.Errorf("proxmox channel: disk-free not ok: %s", resp.Error)
	}
	return resp.ThinDataPct, resp.LocalAvailBytes, nil
}

// Cryptcheck asks the helper to verify the off-site (crypt) archive integrity for
// a VMID. Returns ok and a human-readable detail.
func (c *ProxmoxChannel) Cryptcheck(vmid int) (ok bool, detail string, err error) {
	// cryptcheck can stream/verify a large archive — give it a generous timeout.
	raw, err := c.run(fmt.Sprintf("cryptcheck %d", vmid), 200*time.Second)
	if err != nil {
		return false, "", err
	}
	var resp struct {
		channelEnvelope
		Differences int    `json:"differences"`
		Errors      int    `json:"errors"`
		Detail      string `json:"detail"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return false, "", fmt.Errorf("proxmox channel: decode cryptcheck %q: %w", raw, jerr)
	}
	detail = resp.Detail
	if detail == "" {
		detail = fmt.Sprintf("differences=%d errors=%d", resp.Differences, resp.Errors)
	}
	verified := resp.OK && resp.Differences == 0 && resp.Errors == 0
	return verified, detail, nil
}

// Healthcheck asks the helper to probe a service/port inside a (sandbox) guest.
// kind is "service" or "port"; arg is the service name / port number. The vmid
// MUST be in the sandbox range; the helper enforces it too, but we guard here.
func (c *ProxmoxChannel) Healthcheck(vmid int, gtype, kind, arg string) (ok bool, detail string, err error) {
	if !isSandboxVMID(vmid) {
		return false, "", fmt.Errorf("proxmox channel: healthcheck refused, vmid %d outside sandbox range", vmid)
	}
	op := fmt.Sprintf("healthcheck %d %s %s %s", vmid, gtype, kind, arg)
	raw, err := c.run(op, 30*time.Second)
	if err != nil {
		return false, "", err
	}
	var resp struct {
		channelEnvelope
		Detail string `json:"detail"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return false, "", fmt.Errorf("proxmox channel: decode healthcheck %q: %w", raw, jerr)
	}
	return resp.OK, resp.Detail, nil
}

// Ping returns the lifecycle status of a sandbox guest: "running", "stopped" or
// "absent". Used to find a free sandbox slot and to confirm boot.
func (c *ProxmoxChannel) Ping(vmid int) (status string, err error) {
	if !isSandboxVMID(vmid) {
		return "", fmt.Errorf("proxmox channel: ping refused, vmid %d outside sandbox range", vmid)
	}
	raw, err := c.run(fmt.Sprintf("ping %d", vmid), 30*time.Second)
	if err != nil {
		return "", err
	}
	var resp struct {
		channelEnvelope
		Status string `json:"status"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return "", fmt.Errorf("proxmox channel: decode ping %q: %w", raw, jerr)
	}
	if !resp.OK {
		return "", fmt.Errorf("proxmox channel: ping not ok: %s", resp.Error)
	}
	return resp.Status, nil
}
