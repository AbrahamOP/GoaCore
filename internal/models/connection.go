package models

import "time"

// Connection mirrors one row of the `connections` table: an infrastructure
// service configured in-app (onboarding) rather than (or on top of) environment
// variables. At Jalon 1 the only service is "proxmox"; "wazuh"/"ai"/"discord"
// will be additional rows with no schema change.
//
// SecretEnc holds the AES-256-GCM ciphertext (base64) of the service secret —
// it is NEVER exposed to templates or logs, and the decrypted value lives only
// in memory. URL/Node/TokenID and the non-sensitive Extra fields stay in clear.
type Connection struct {
	Service      string
	Enabled      bool
	URL          string
	Node         string
	TokenID      string
	SecretEnc    string
	Extra        map[string]string
	Configured   bool
	Status       string
	LastTestedAt *time.Time
	LastError    string
	Source       string
	UpdatedBy    string
	UpdatedAt    time.Time
}

// ProxmoxConnectionForm binds the onboarding POST body for the Proxmox service.
// TokenSecret is the plaintext token secret as typed by the admin; it is
// encrypted before persistence and must never be logged.
type ProxmoxConnectionForm struct {
	URL         string
	Node        string
	TokenID     string
	TokenSecret string
	Storage     string
	Bridge      string
}
