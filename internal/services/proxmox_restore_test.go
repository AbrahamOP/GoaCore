package services

import (
	"testing"

	"goacloud/internal/config"
)

// TestResolveRestoreStorage_Overrides covers the no-network branches of the
// resolution order: a dedicated restore_storage wins, else the creation storage,
// before any auto-detection is attempted. The auto-detect + literal floor branch is
// network-bound (live Proxmox) and is exercised by detectStorage's own tests; here
// we assert the precedence that must short-circuit before any API call.
func TestResolveRestoreStorage_Overrides(t *testing.T) {
	p := NewProxmoxService(nil, true)

	// 1. Dedicated restore_storage override wins over pm.Storage.
	pm := config.ProxmoxConn{Storage: "create-lvm", RestoreStorage: "restore-zfs"}
	if got := p.resolveRestoreStorage(pm, "qemu"); got != "restore-zfs" {
		t.Errorf("restore_storage override = %q, want restore-zfs", got)
	}

	// 2. No dedicated restore_storage → fall back to the creation storage (pm.Storage),
	// still without touching the network.
	pm = config.ProxmoxConn{Storage: "create-lvm"}
	if got := p.resolveRestoreStorage(pm, "lxc"); got != "create-lvm" {
		t.Errorf("pm.Storage fallback = %q, want create-lvm", got)
	}
}

func TestIsSandboxVMID(t *testing.T) {
	tests := []struct {
		name string
		vmid int
		want bool
	}{
		{"below range lower bound", 9499, false},
		{"lower bound inclusive", 9500, true},
		{"mid range", 9550, true},
		{"upper bound inclusive", 9599, true},
		{"above range upper bound", 9600, false},
		{"zero", 0, false},
		{"negative", -1, false},
		{"production guest 110", 110, false},
		{"production guest 100", 100, false},
		{"large out of range", 100000, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSandboxVMID(tc.vmid); got != tc.want {
				t.Fatalf("isSandboxVMID(%d) = %v, want %v", tc.vmid, got, tc.want)
			}
		})
	}
}

func TestBuildSandboxNetN(t *testing.T) {
	tests := []struct {
		name    string
		current string
		pveType string
		vlan    int
		bridge  string
		want    string
	}{
		{"lxc empty fallback", "", "lxc", 99, "vmbr1", "name=eth0,bridge=vmbr1,tag=99"},
		{"qemu empty fallback", "", "qemu", 99, "vmbr1", "virtio,bridge=vmbr1,tag=99"},
		{
			"lxc replace existing tag and bridge",
			"name=eth0,bridge=vmbr0,ip=192.168.20.11/24,tag=20",
			"lxc", 99, "vmbr1",
			"name=eth0,bridge=vmbr1,ip=192.168.20.11/24,tag=99",
		},
		{
			"qemu add tag, keep model+mac",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
			"qemu", 99, "vmbr1",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1,tag=99",
		},
		{
			"no bridge present gets one",
			"name=eth0,ip=dhcp",
			"lxc", 99, "vmbr1",
			"name=eth0,ip=dhcp,bridge=vmbr1,tag=99",
		},
		{
			// Jalon 2: a custom sandbox bridge is honoured (override/pm.Bridge), and a
			// restored prod NIC's bridge is rewritten to it — never kept.
			"custom sandbox bridge rewrites prod bridge",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=20",
			"qemu", 42, "vmbr9",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr9,tag=42",
		},
		{
			// Empty bridge floors to the hard vmbr1 fallback — never bridgeless.
			"empty bridge floors to vmbr1",
			"name=eth0,ip=dhcp",
			"lxc", 99, "",
			"name=eth0,ip=dhcp,bridge=vmbr1,tag=99",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSandboxNetN(tc.current, tc.pveType, tc.vlan, tc.bridge)
			if got != tc.want {
				t.Fatalf("buildSandboxNetN(%q,%q,%d,%q) = %q, want %q", tc.current, tc.pveType, tc.vlan, tc.bridge, got, tc.want)
			}
		})
	}
}
