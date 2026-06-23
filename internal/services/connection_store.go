package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"goacloud/internal/config"
	"goacloud/internal/models"
)

// serviceProxmox is the connections.service key for the Proxmox row.
const serviceProxmox = "proxmox"

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
	conn, err := s.getConnection(serviceProxmox)
	if err != nil {
		return nil, "", err
	}
	if conn == nil {
		return nil, "", nil
	}
	secret, derr := s.enc.DecryptData(conn.SecretEnc)
	if derr != nil {
		// Undecipherable secret (e.g. SESSION_SECRET changed). Surface it as an
		// errored, unconfigured connection rather than crashing.
		return conn, "", fmt.Errorf("decrypt proxmox secret: %w", derr)
	}
	return conn, secret, nil
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
	secretEnc, err := s.enc.EncryptData(form.TokenSecret)
	if err != nil {
		return fmt.Errorf("encrypt proxmox secret: %w", err)
	}
	extra, err := json.Marshal(map[string]string{
		"storage": form.Storage,
		"bridge":  form.Bridge,
	})
	if err != nil {
		return fmt.Errorf("marshal proxmox extra: %w", err)
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
		serviceProxmox, form.URL, form.Node, form.TokenID, secretEnc, string(extra), source, updatedBy)
	if err != nil {
		return fmt.Errorf("save proxmox connection: %w", err)
	}
	return nil
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
	res, err := s.db.Exec(`DELETE FROM connections WHERE service = ?`, serviceProxmox)
	if err != nil {
		return 0, fmt.Errorf("delete proxmox connection: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
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
	}
	return s.saveProxmox(form, "import-env", "env")
}

// ProxmoxExtra extracts the storage/bridge values from a loaded connection's
// extra_json, with safe empty-string fallbacks.
func ProxmoxExtra(c *models.Connection) (storage, bridge string) {
	if c == nil || c.Extra == nil {
		return "", ""
	}
	return c.Extra["storage"], c.Extra["bridge"]
}
