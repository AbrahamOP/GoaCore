package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"goacloud/internal/config"
	"goacloud/internal/models"
)

// connections.service keys. One row per service; absence of a row means
// "not configured" (there is deliberately no INSERT IGNORE seeding any of them).
const (
	serviceProxmox          = "proxmox"
	serviceWazuh            = "wazuh"
	serviceWazuhIndexer     = "wazuh-indexer"
	serviceAI               = "ai"
	serviceDiscord          = "discord"
	serviceGoabackupChannel = "goabackup-channel"
)

// ConnectionStore persists per-service infrastructure credentials in the
// `connections` table. Only the service secret is encrypted (AES-256-GCM, same
// key as SSH keys) via the injected *SSHService crypto helpers; every other field
// is stored in clear. The store NEVER returns or logs the encrypted blob in clear
// except through the explicit decrypted secret returned by GetProxmox.
type ConnectionStore struct {
	db  *sql.DB
	enc *SSHService
}

// NewConnectionStore builds a ConnectionStore. enc supplies EncryptData/DecryptData
// (reuses the SSH service AES-256-GCM key derived from SESSION_SECRET).
func NewConnectionStore(db *sql.DB, enc *SSHService) *ConnectionStore {
	return &ConnectionStore{db: db, enc: enc}
}

// GetProxmox loads the 'proxmox' connection row and decrypts its secret. It
// returns (nil, "", nil) when no row exists (the clean "not configured" signal).
//
// A decryption failure is NEVER fatal and never panics: it returns the row with an
// empty secret and a non-nil error so the caller can mark the connection as
// errored and fall back to "not configured" (re-onboard). This is the SESSION_SECRET
// rotation case — the ciphertext became undecipherable, exactly like SSH/MFA secrets.
func (s *ConnectionStore) GetProxmox() (*models.Connection, string, error) {
	return s.getDecrypted(serviceProxmox)
}

// getConnection reads a single connections row by service key. Returns (nil, nil)
// when the row is absent.
func (s *ConnectionStore) getConnection(service string) (*models.Connection, error) {
	var (
		c          models.Connection
		enabled    bool
		configured bool
		extraRaw   sql.NullString
		lastTested sql.NullTime
	)
	err := s.db.QueryRow(
		`SELECT service, enabled, url, node, token_id, secret_enc, extra_json,
		        configured, status, last_tested_at, last_error, source, updated_by, updated_at
		 FROM connections WHERE service = ?`, service).
		Scan(&c.Service, &enabled, &c.URL, &c.Node, &c.TokenID, &c.SecretEnc, &extraRaw,
			&configured, &c.Status, &lastTested, &c.LastError, &c.Source, &c.UpdatedBy, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load connection %q: %w", service, err)
	}
	c.Enabled = enabled
	c.Configured = configured
	if lastTested.Valid {
		c.LastTestedAt = &lastTested.Time
	}
	if extraRaw.Valid && extraRaw.String != "" {
		m := map[string]string{}
		if jerr := json.Unmarshal([]byte(extraRaw.String), &m); jerr == nil {
			c.Extra = m
		}
	}
	return &c, nil
}

// SaveProxmox encrypts the token secret and upserts the 'proxmox' connection row.
// The row is marked configured=1 / status='ok' (a successful live test is the
// precondition enforced by the caller). storage/bridge are stored in extra_json so
// future non-secret fields need no schema change. source defaults to 'db'.
func (s *ConnectionStore) SaveProxmox(form models.ProxmoxConnectionForm, updatedBy string) error {
	return s.saveProxmox(form, updatedBy, "db")
}

func (s *ConnectionStore) saveProxmox(form models.ProxmoxConnectionForm, updatedBy, source string) error {
	// extra_json is a clear-text blob (no secret ever lands here — the token secret
	// goes to the encrypted secret_enc column). storage/bridge predate Jalon 2; the
	// restore-test sandbox attributes are appended beside them with no schema change.
	//
	// The sandbox bridge has its OWN key ("sandbox_bridge"), DELIBERATELY separate from
	// the creation "bridge" key: the two must never share a value, otherwise a creation
	// bridge of vmbr0 (prod) would silently become the isolation bridge and a restored
	// prod guest could boot onto a live segment. We persist sandbox_bridge / sandbox_vlan
	// only when set so an unset value falls through to the env/hard-default layer
	// (vmbr1 / VLAN 99) at resolution time — never inheriting pm.Bridge.
	extra := map[string]string{
		"storage":         form.Storage,
		"bridge":          form.Bridge,
		"restore_storage": form.RestoreStorage,
		"crypt_remote":    form.CryptRemote,
	}
	if form.SandboxBridge != "" {
		extra["sandbox_bridge"] = form.SandboxBridge
	}
	if form.SandboxVlan > 0 {
		extra["sandbox_vlan"] = strconv.Itoa(form.SandboxVlan)
	}
	return s.save(serviceProxmox, form.URL, form.Node, form.TokenID, form.TokenSecret,
		extra, updatedBy, source)
}

// save is the generic, service-neutral upsert behind every Save* wrapper. It
// encrypts the secret (AES-256-GCM, SESSION_SECRET-derived key), marshals the
// non-secret extra map to extra_json, and upserts the connections row marked
// configured=1 / status='ok' (a successful live test is the caller's precondition,
// exactly like the Proxmox path). node is unused by the non-Proxmox services and
// stored empty for them. The SQL is identical to the original Proxmox upsert.
func (s *ConnectionStore) save(service, url, node, tokenID, secret string, extra map[string]string, updatedBy, source string) error {
	secretEnc, err := s.enc.EncryptData(secret)
	if err != nil {
		return fmt.Errorf("encrypt %s secret: %w", service, err)
	}
	if extra == nil {
		extra = map[string]string{}
	}
	extraJSON, err := json.Marshal(extra)
	if err != nil {
		return fmt.Errorf("marshal %s extra: %w", service, err)
	}
	_, err = s.db.Exec(
		`INSERT INTO connections
		   (service, enabled, url, node, token_id, secret_enc, extra_json,
		    configured, status, last_tested_at, last_error, source, updated_by)
		 VALUES (?, 1, ?, ?, ?, ?, ?, 1, 'ok', NOW(), '', ?, ?)
		 ON DUPLICATE KEY UPDATE
		   enabled = 1, url = VALUES(url), node = VALUES(node), token_id = VALUES(token_id),
		   secret_enc = VALUES(secret_enc), extra_json = VALUES(extra_json),
		   configured = 1, status = 'ok', last_tested_at = NOW(), last_error = '',
		   source = VALUES(source), updated_by = VALUES(updated_by)`,
		service, url, node, tokenID, secretEnc, string(extraJSON), source, updatedBy)
	if err != nil {
		return fmt.Errorf("save %s connection: %w", service, err)
	}
	return nil
}

// getDecrypted loads a connection row and decrypts its secret. It returns
// (nil, "", nil) when no row exists (clean "not configured"), and on an
// undecipherable secret returns (conn, "", err) — never fatal, never a panic
// (the SESSION_SECRET-rotation case). It is the generic engine behind every
// Get* wrapper, identical in contract to GetProxmox.
func (s *ConnectionStore) getDecrypted(service string) (*models.Connection, string, error) {
	conn, err := s.getConnection(service)
	if err != nil {
		return nil, "", err
	}
	if conn == nil {
		return nil, "", nil
	}
	secret, derr := s.enc.DecryptData(conn.SecretEnc)
	if derr != nil {
		return conn, "", fmt.Errorf("decrypt %s secret: %w", service, derr)
	}
	return conn, secret, nil
}

// delete removes a connection row by service key and returns the rows deleted.
// It is the generic engine behind every Delete* wrapper.
func (s *ConnectionStore) delete(service string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM connections WHERE service = ?`, service)
	if err != nil {
		return 0, fmt.Errorf("delete %s connection: %w", service, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SetStatus records the outcome of the most recent live test for a service. It is
// best-effort metadata (status/last_error/last_tested_at) and never touches the
// secret or the configured flag.
func (s *ConnectionStore) SetStatus(service, status, lastErr string) error {
	_, err := s.db.Exec(
		`UPDATE connections SET status = ?, last_error = ?, last_tested_at = NOW() WHERE service = ?`,
		status, lastErr, service)
	if err != nil {
		return fmt.Errorf("set connection status %q: %w", service, err)
	}
	return nil
}

// DeleteProxmox removes the 'proxmox' connection row. This is the documented
// rollback: with the row gone, ReloadProxmox falls back to the env values at the
// next boot (or the live snapshot keeps the env value until then). Returns the
// number of rows deleted.
func (s *ConnectionStore) DeleteProxmox() (int64, error) {
	return s.delete(serviceProxmox)
}

// ImportFromEnv seeds the 'proxmox' connection row from the environment-derived
// config in one explicit click (never automatic). The env token secret is encrypted
// on the way in; source is recorded as 'env' for audit. It returns an error if the
// env config has no Proxmox URL+token to import.
func (s *ConnectionStore) ImportFromEnv(cfg *config.Config) error {
	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		return errors.New("no Proxmox configuration in environment to import")
	}
	form := models.ProxmoxConnectionForm{
		URL:         cfg.ProxmoxURL,
		Node:        cfg.ProxmoxNode,
		TokenID:     cfg.ProxmoxTokenID,
		TokenSecret: cfg.ProxmoxTokenSecret,
		Storage:     cfg.ProxmoxStorage,
		Bridge:      cfg.ProxmoxBridge,
		// Carry the env-seeded restore-test attributes into the DB row so an
		// import-then-DB-source transition preserves them (CryptRemote has no env
		// yet → stays empty → hard default at resolution time). SandboxBridge comes
		// from its OWN env (GOABACKUP_SANDBOX_BRIDGE), never from ProxmoxBridge.
		SandboxVlan:    cfg.SandboxVlan,
		RestoreStorage: cfg.RestoreStorage,
		SandboxBridge:  cfg.SandboxBridge,
	}
	return s.saveProxmox(form, "import-env", "env")
}

// ProxmoxExtra extracts the storage/bridge values from a loaded connection's
// extra_json, with safe empty-string fallbacks. It is the narrow, Jalon-1 reader
// kept for callers that only need the creation storage/bridge.
func ProxmoxExtra(c *models.Connection) (storage, bridge string) {
	if c == nil || c.Extra == nil {
		return "", ""
	}
	return c.Extra["storage"], c.Extra["bridge"]
}

// ProxmoxSandboxExtra extracts the Jalon-2 restore-test sandbox attributes from a
// loaded connection's extra_json, with safe fallbacks (empty strings / 0 VLAN). A
// malformed sandbox_vlan parses to 0, which the resolver floors back to the hard
// default — never a silent "no isolation". sandbox_bridge is its own dedicated key
// (empty ⇒ hard vmbr1 fallback, never the creation bridge). It is deliberately
// separate from ProxmoxExtra so the two well-understood Jalon-1 callers stay
// untouched in shape.
func ProxmoxSandboxExtra(c *models.Connection) (restoreStorage, cryptRemote, sandboxBridge string, sandboxVlan int) {
	if c == nil || c.Extra == nil {
		return "", "", "", 0
	}
	v, _ := strconv.Atoi(c.Extra["sandbox_vlan"]) // "" or garbage ⇒ 0 ⇒ hard default
	return c.Extra["restore_storage"], c.Extra["crypt_remote"], c.Extra["sandbox_bridge"], v
}

// --- Wazuh Indexer quartet (service='wazuh-indexer') ---

// GetWazuhIndexer loads the 'wazuh-indexer' row and decrypts its password. Same
// contract as GetProxmox: (nil,"",nil) when absent, (conn,"",err) on an
// undecipherable secret (never fatal).
func (s *ConnectionStore) GetWazuhIndexer() (*models.Connection, string, error) {
	return s.getDecrypted(serviceWazuhIndexer)
}

// SaveWazuhIndexer encrypts the password and upserts the 'wazuh-indexer' row.
func (s *ConnectionStore) SaveWazuhIndexer(form models.WazuhIndexerConnectionForm, updatedBy string) error {
	return s.saveWazuhIndexer(form, updatedBy, "db")
}

func (s *ConnectionStore) saveWazuhIndexer(form models.WazuhIndexerConnectionForm, updatedBy, source string) error {
	return s.save(serviceWazuhIndexer, form.URL, "", form.User, form.Password, nil, updatedBy, source)
}

// DeleteWazuhIndexer removes the 'wazuh-indexer' row (rollback to env at next boot
// / live RollbackToEnv via the registry).
func (s *ConnectionStore) DeleteWazuhIndexer() (int64, error) {
	return s.delete(serviceWazuhIndexer)
}

// ImportFromEnvWazuhIndexer seeds the 'wazuh-indexer' row from the environment in
// one explicit click. Errors when the env carries no Wazuh Indexer URL.
func (s *ConnectionStore) ImportFromEnvWazuhIndexer(cfg *config.Config) error {
	if cfg.WazuhIndexerURL == "" {
		return errors.New("no Wazuh Indexer configuration in environment to import")
	}
	form := models.WazuhIndexerConnectionForm{
		URL:      cfg.WazuhIndexerURL,
		User:     cfg.WazuhIndexerUser,
		Password: cfg.WazuhIndexerPass,
	}
	return s.saveWazuhIndexer(form, "import-env", "env")
}

// --- Wazuh API quartet (service='wazuh') ---

// GetWazuh loads the 'wazuh' row and decrypts its password.
func (s *ConnectionStore) GetWazuh() (*models.Connection, string, error) {
	return s.getDecrypted(serviceWazuh)
}

// SaveWazuh encrypts the password and upserts the 'wazuh' row.
func (s *ConnectionStore) SaveWazuh(form models.WazuhConnectionForm, updatedBy string) error {
	return s.saveWazuh(form, updatedBy, "db")
}

func (s *ConnectionStore) saveWazuh(form models.WazuhConnectionForm, updatedBy, source string) error {
	return s.save(serviceWazuh, form.URL, "", form.User, form.Password, nil, updatedBy, source)
}

// DeleteWazuh removes the 'wazuh' row.
func (s *ConnectionStore) DeleteWazuh() (int64, error) {
	return s.delete(serviceWazuh)
}

// ImportFromEnvWazuh seeds the 'wazuh' row from the environment.
func (s *ConnectionStore) ImportFromEnvWazuh(cfg *config.Config) error {
	if cfg.WazuhAPIURL == "" {
		return errors.New("no Wazuh API configuration in environment to import")
	}
	form := models.WazuhConnectionForm{
		URL:      cfg.WazuhAPIURL,
		User:     cfg.WazuhUser,
		Password: cfg.WazuhPassword,
	}
	return s.saveWazuh(form, "import-env", "env")
}

// --- AI quartet (service='ai') ---

// GetAI loads the 'ai' row and decrypts its api_key (empty for Ollama).
func (s *ConnectionStore) GetAI() (*models.Connection, string, error) {
	return s.getDecrypted(serviceAI)
}

// SaveAI encrypts the api_key (may be empty for Ollama) and upserts the 'ai' row.
// provider and openai_base are non-secret and stored in extra_json.
func (s *ConnectionStore) SaveAI(form models.AIConnectionForm, updatedBy string) error {
	return s.saveAI(form, updatedBy, "db")
}

func (s *ConnectionStore) saveAI(form models.AIConnectionForm, updatedBy, source string) error {
	extra := map[string]string{
		"provider":    form.Provider,
		"openai_base": form.OpenAIBaseURL,
	}
	return s.save(serviceAI, form.URL, "", form.Model, form.APIKey, extra, updatedBy, source)
}

// DeleteAI removes the 'ai' row.
func (s *ConnectionStore) DeleteAI() (int64, error) {
	return s.delete(serviceAI)
}

// ImportFromEnvAI seeds the 'ai' row from the environment. It accepts Ollama with
// only a URL (no key) as well as OpenAI with a key; it errors only when there is
// nothing usable to import (no provider/url/key at all).
func (s *ConnectionStore) ImportFromEnvAI(cfg *config.Config) error {
	if cfg.AIProvider == "" && cfg.AIURL == "" && cfg.AIAPIKey == "" {
		return errors.New("no AI configuration in environment to import")
	}
	form := models.AIConnectionForm{
		Provider:      cfg.AIProvider,
		URL:           cfg.AIURL,
		APIKey:        cfg.AIAPIKey,
		Model:         cfg.AIModel,
		OpenAIBaseURL: cfg.OpenAIBaseURL,
	}
	return s.saveAI(form, "import-env", "env")
}

// AIExtra extracts the provider/openai_base values from an 'ai' connection's
// extra_json, with safe empty-string fallbacks.
func AIExtra(c *models.Connection) (provider, openaiBase string) {
	if c == nil || c.Extra == nil {
		return "", ""
	}
	return c.Extra["provider"], c.Extra["openai_base"]
}

// --- Discord quartet (service='discord') ---

// GetDiscord loads the 'discord' row and decrypts its bot token.
func (s *ConnectionStore) GetDiscord() (*models.Connection, string, error) {
	return s.getDecrypted(serviceDiscord)
}

// SaveDiscord encrypts the bot token and upserts the 'discord' row. channel id is
// stored in token_id; the auth/ansible channels are non-secret extra_json fields.
func (s *ConnectionStore) SaveDiscord(form models.DiscordConnectionForm, updatedBy string) error {
	return s.saveDiscord(form, updatedBy, "db")
}

func (s *ConnectionStore) saveDiscord(form models.DiscordConnectionForm, updatedBy, source string) error {
	extra := map[string]string{
		"auth_channel":    form.AuthChannelID,
		"ansible_channel": form.AnsibleChannelID,
	}
	return s.save(serviceDiscord, "", "", form.ChannelID, form.Token, extra, updatedBy, source)
}

// DeleteDiscord removes the 'discord' row.
func (s *ConnectionStore) DeleteDiscord() (int64, error) {
	return s.delete(serviceDiscord)
}

// ImportFromEnvDiscord seeds the 'discord' row from the environment. Errors when
// the env carries no token or no main channel id (the minimum a bot needs).
func (s *ConnectionStore) ImportFromEnvDiscord(cfg *config.Config) error {
	if cfg.DiscordBotToken == "" || cfg.DiscordChannelID == "" {
		return errors.New("no Discord configuration in environment to import")
	}
	form := models.DiscordConnectionForm{
		Token:            cfg.DiscordBotToken,
		ChannelID:        cfg.DiscordChannelID,
		AuthChannelID:    cfg.DiscordAuthChannel,
		AnsibleChannelID: cfg.DiscordAnsibleChannel,
	}
	return s.saveDiscord(form, "import-env", "env")
}

// DiscordExtra extracts the auth/ansible channel ids from a 'discord' connection's
// extra_json, with safe empty-string fallbacks.
func DiscordExtra(c *models.Connection) (authChannel, ansibleChannel string) {
	if c == nil || c.Extra == nil {
		return "", ""
	}
	return c.Extra["auth_channel"], c.Extra["ansible_channel"]
}

// --- Goabackup channel quartet (service='goabackup-channel') ---
//
// The read-only Proxmox helper channel persists the in-app-generated ed25519 KEY,
// not an admin-typed credential. The OpenSSH private-key PEM is the encrypted secret
// (secret_enc); the PUBLIC key, fingerprint and key type are non-secrets carried in
// extra_json so the install endpoint and the UI can read them WITHOUT ever touching
// the private key. The channel target is url=host("ip:port") / token_id=user. ZERO
// schema migration — this is the generic save()/getDecrypted()/delete() reused.

// GetGoabackupChannel loads the 'goabackup-channel' row and decrypts its private
// key PEM. Same contract as GetProxmox: (nil,"",nil) when absent (clean "not
// configured" → the channel falls back to GOABACKUP_SSH_KEY_FILE), and on an
// undecipherable secret (SESSION_SECRET rotation) returns (conn,"",err) — never
// fatal, never a panic. The caller marks the channel errored and re-provisions.
func (s *ConnectionStore) GetGoabackupChannel() (*models.Connection, string, error) {
	return s.getDecrypted(serviceGoabackupChannel)
}

// SaveGoabackupChannel encrypts the private key PEM and upserts the
// 'goabackup-channel' row (OVERWRITE, ON DUPLICATE KEY UPDATE — a rotation replaces
// the single row, it never appends). The public key, fingerprint and key type go in
// clear to extra_json; the private PEM goes ONLY to the encrypted secret column and
// is never mirrored into extra_json. source='db'.
func (s *ConnectionStore) SaveGoabackupChannel(form models.GoabackupChannelForm, updatedBy string) error {
	return s.saveGoabackupChannel(form, updatedBy, "db")
}

func (s *ConnectionStore) saveGoabackupChannel(form models.GoabackupChannelForm, updatedBy, source string) error {
	// extra_json is the CLEAR (non-secret) blob: the authorized_keys public line, its
	// SHA256 fingerprint and the key type. The private PEM is the encrypted secret and
	// must NEVER appear here (it would defeat the at-rest encryption).
	extra := map[string]string{
		"pubkey":      form.PublicKey,
		"fingerprint": form.Fingerprint,
		"keytype":     form.KeyType,
	}
	return s.save(serviceGoabackupChannel, form.Host, "", form.User, form.PrivateKeyPEM,
		extra, updatedBy, source)
}

// DeleteGoabackupChannel removes the 'goabackup-channel' row. This is the documented
// rollback: with the row gone, the channel falls back to the env GOABACKUP_SSH_*
// (keyFile) at the next boot, or the live registry publishes the env channel via
// RollbackToEnv. NOTE: deleting the DB row does NOT remove the authorized_keys line
// on the Proxmox host — host-side revocation is a separate manual procedure shown in
// the UI at delete time.
func (s *ConnectionStore) DeleteGoabackupChannel() (int64, error) {
	return s.delete(serviceGoabackupChannel)
}

// ImportFromEnvGoabackupChannel seeds the 'goabackup-channel' row from the
// environment in one explicit click. CRITICAL nuance: the env carries a key FILE
// PATH (GOABACKUP_SSH_KEY_FILE), NOT a private-key PEM, so this import records only
// the host/user (source='env') with an EMPTY secret and empty extra. The empty
// secret deliberately signals "no in-DB key" so the channel falls back to the env
// keyFile at runtime — it never fabricates a phantom key. It errors when the env has
// no host to import. (To put a real key in the DB, the admin uses provision, which
// generates + encrypts a fresh ed25519 pair.)
func (s *ConnectionStore) ImportFromEnvGoabackupChannel(cfg *config.Config) error {
	if cfg.GoabackupSSHHost == "" {
		return errors.New("no goabackup channel configuration in environment to import")
	}
	host := cfg.GoabackupSSHHost
	form := models.GoabackupChannelForm{
		Host: host,
		User: cfg.GoabackupSSHUser,
		// No PEM/pubkey/fingerprint: the env path keeps using the key FILE, not a DB
		// key. Empty secret ⇒ the channel resolver reads GOABACKUP_SSH_KEY_FILE.
	}
	return s.saveGoabackupChannel(form, "import-env", "env")
}

// GoabackupChannelExtra extracts the non-secret pubkey / fingerprint / keytype from a
// loaded 'goabackup-channel' connection's extra_json, with safe empty-string
// fallbacks. The private key is NEVER reachable through this reader — it lives only
// in the encrypted secret_enc column, surfaced solely by GetGoabackupChannel.
func GoabackupChannelExtra(c *models.Connection) (pubkey, fingerprint, keytype string) {
	if c == nil || c.Extra == nil {
		return "", "", ""
	}
	return c.Extra["pubkey"], c.Extra["fingerprint"], c.Extra["keytype"]
}
