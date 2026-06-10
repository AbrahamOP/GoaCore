package workers

import "testing"

func TestProxmoxExtractUser(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "quoted user",
			line: "pvedaemon[1234]: successful auth for user 'root@pam'",
			want: "root@pam",
		},
		{
			name: "quoted user followed by text",
			line: "authentication failure; rhost=1.2.3.4 for user 'claude@pve' msg=bad",
			want: "claude@pve",
		},
		{
			name: "unquoted user terminated by space",
			line: "login attempt for user antoine from 10.0.0.5",
			want: "antoine",
		},
		{
			name: "user marker without the 'for user' prefix is ignored",
			line: "authentication failure for rhost=1.2.3.4 user 'bob@pam'",
			want: "inconnu",
		},
		{
			name: "no user marker",
			line: "pvedaemon: some unrelated log line",
			want: "inconnu",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxmoxExtractUser(tt.line); got != tt.want {
				t.Errorf("proxmoxExtractUser(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}
