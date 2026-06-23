package config

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "all empty is valid (optional services)",
			cfg:  Config{},
		},
		{
			name: "valid https urls",
			cfg: Config{
				ProxmoxURL:      "https://192.168.40.20:8006",
				WazuhAPIURL:     "https://192.168.30.10:55000",
				WazuhIndexerURL: "https://192.168.30.10:9200",
				AIURL:           "http://192.168.20.10:11434",
			},
		},
		{
			name:    "missing scheme on a blocking URL (Wazuh) is fatal",
			cfg:     Config{WazuhAPIURL: "192.168.30.10:55000"},
			wantErr: true,
		},
		{
			name:    "missing host",
			cfg:     Config{WazuhAPIURL: "https://"},
			wantErr: true,
		},
		{
			name:    "garbage url",
			cfg:     Config{AIURL: "ht!tp://%zz"},
			wantErr: true,
		},
		{
			// Since Jalon 1 a malformed PROXMOX_URL from the env is NOT fatal: the
			// connection can be (re)configured in-app, so Validate must not block boot.
			name: "malformed PROXMOX_URL is no longer fatal",
			cfg:  Config{ProxmoxURL: "192.168.40.20:8006"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	good := []string{"https://192.168.40.20:8006", "http://host", "https://h:9200/path"}
	bad := []string{"192.168.40.20:8006", "https://", "ht!tp://%zz", ""}
	for _, u := range good {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", u)
		}
	}
}

func TestProxmoxURLWarning(t *testing.T) {
	if w := (&Config{}).ProxmoxURLWarning(); w != "" {
		t.Errorf("empty PROXMOX_URL should not warn, got %q", w)
	}
	if w := (&Config{ProxmoxURL: "https://192.168.40.20:8006"}).ProxmoxURLWarning(); w != "" {
		t.Errorf("valid PROXMOX_URL should not warn, got %q", w)
	}
	if w := (&Config{ProxmoxURL: "192.168.40.20:8006"}).ProxmoxURLWarning(); w == "" {
		t.Error("malformed PROXMOX_URL should warn, got empty")
	}
}
