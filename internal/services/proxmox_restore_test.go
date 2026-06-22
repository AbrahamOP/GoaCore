package services

import "testing"

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
		want    string
	}{
		{"lxc empty fallback", "", "lxc", 99, "name=eth0,bridge=vmbr1,tag=99"},
		{"qemu empty fallback", "", "qemu", 99, "virtio,bridge=vmbr1,tag=99"},
		{
			"lxc replace existing tag and bridge",
			"name=eth0,bridge=vmbr0,ip=192.168.20.11/24,tag=20",
			"lxc", 99,
			"name=eth0,bridge=vmbr1,ip=192.168.20.11/24,tag=99",
		},
		{
			"qemu add tag, keep model+mac",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
			"qemu", 99,
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1,tag=99",
		},
		{
			"no bridge present gets one",
			"name=eth0,ip=dhcp",
			"lxc", 99,
			"name=eth0,ip=dhcp,bridge=vmbr1,tag=99",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSandboxNetN(tc.current, tc.pveType, tc.vlan)
			if got != tc.want {
				t.Fatalf("buildSandboxNetN(%q,%q,%d) = %q, want %q", tc.current, tc.pveType, tc.vlan, got, tc.want)
			}
		})
	}
}
