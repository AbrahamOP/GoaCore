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

	// Restore-test "Réglages avancés" (Jalon 2), persisted in extra_json beside
	// storage/bridge — none are secrets. SandboxVlan is the isolation VLAN forced on
	// sandbox guests (0/empty ⇒ hard fallback 99 at resolution time). RestoreStorage
	// overrides the storage a restore-test guest is restored into (empty ⇒ pm.Storage
	// then auto-detect). SandboxBridge is the bridge that must carry the isolation
	// VLAN (empty ⇒ pm.Bridge then the hard vmbr1 fallback; never freely
	// auto-detected, to avoid landing the sandbox on a prod bridge). CryptRemote is
	// the rclone remote the N1 off-site check targets (empty ⇒ hard default gcrypt).
	SandboxVlan    int
	RestoreStorage string
	SandboxBridge  string
	CryptRemote    string
}

// WazuhConnectionForm binds the onboarding POST body for the Wazuh Manager API.
// Password is the plaintext API password as typed by the admin; it is encrypted
// before persistence (the connections.secret_enc column) and must never be logged.
// It maps to the 'wazuh' connection row (url=API URL, token_id=user, secret=pass).
type WazuhConnectionForm struct {
	URL      string
	User     string
	Password string
}

// WazuhIndexerConnectionForm binds the onboarding POST body for the Wazuh Indexer
// (OpenSearch) API. Password is the plaintext Basic-auth password; it is encrypted
// before persistence. It maps to the 'wazuh-indexer' connection row, deliberately
// distinct from 'wazuh' (two endpoints, two creds, two independent live tests).
type WazuhIndexerConnectionForm struct {
	URL      string
	User     string
	Password string
}

// AIConnectionForm binds the onboarding POST body for the AI enrichment provider.
// APIKey is the plaintext provider key (OpenAI) and is the encrypted secret; for
// Ollama it is empty. Provider toggles which fields matter (URL for Ollama,
// APIKey+OpenAIBaseURL for OpenAI). It maps to the 'ai' connection row
// (url=AIURL, token_id=model, secret=api_key, extra={provider,openai_base}).
type AIConnectionForm struct {
	Provider      string
	URL           string
	APIKey        string
	Model         string
	OpenAIBaseURL string
}

// GoabackupChannelForm binds the persisted state of the read-only Proxmox helper
// channel (service='goabackup-channel'). Unlike the other services, the secret here
// is NOT typed by an admin: PrivateKeyPEM is the OpenSSH-format ed25519 private key
// GoaCloud GENERATES in-app (GenerateEd25519Key) and encrypts before persistence — it
// must NEVER be logged, echoed, or returned by any GET/test. Host is "ip:port" (the
// channel target), User is the SSH login ("goabackup"), and PublicKey/Fingerprint/
// KeyType are NON-secret values mirrored into extra_json for the install script + UI
// (the private key never lands in extra_json). It maps to the 'goabackup-channel'
// connection row (url=host, token_id=user, secret=private PEM,
// extra={pubkey,fingerprint,keytype}).
type GoabackupChannelForm struct {
	Host          string
	User          string
	PrivateKeyPEM string
	PublicKey     string
	Fingerprint   string
	KeyType       string
}

// DiscordConnectionForm binds the onboarding POST body for the Discord bot.
// Token is the plaintext bot token and is the encrypted secret; it must never be
// logged or echoed. It maps to the 'discord' connection row (token_id=channel id,
// secret=bot token, extra={auth_channel,ansible_channel}).
type DiscordConnectionForm struct {
	Token            string
	ChannelID        string
	AuthChannelID    string
	AnsibleChannelID string
}
