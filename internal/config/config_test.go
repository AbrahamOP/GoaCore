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
			name:    "missing scheme",
			cfg:     Config{ProxmoxURL: "192.168.40.20:8006"},
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
