package services

import (
	"fmt"
	"sync"
	"testing"

	"goacloud/internal/models"
)

// noopLogf is a logf stub for tests.
func noopLogf(string, ...any) {}

// newTestBackupService builds a BackupService with just the in-process maps wired,
// enough to exercise the concurrency / reconciliation helpers without any DB,
// Proxmox or Discord dependency.
func newTestBackupService() *BackupService {
	return &BackupService{
		testInFlight: make(map[int]bool),
		sandboxInUse: make(map[int]bool),
	}
}

// TestPickFreeSandboxVMID_SkipsReservedAndPresent verifies the picker honours both
// the in-process reservation map and the Proxmox "present" status.
func TestPickFreeSandboxVMID_SkipsReservedAndPresent(t *testing.T) {
	s := newTestBackupService()
	// Pre-reserve the first two slots in-process.
	s.sandboxInUse[sandboxVMIDMin] = true
	s.sandboxInUse[sandboxVMIDMin+1] = true

	// Ping reports the next two as present (running/stopped), then absent.
	ping := func(vmid int) (string, error) {
		switch vmid {
		case sandboxVMIDMin + 2:
			return "running", nil
		case sandboxVMIDMin + 3:
			return "stopped", nil
		default:
			return "absent", nil
		}
	}

	got, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := sandboxVMIDMin + 4
	if got != want {
		t.Fatalf("picked %d, want %d", got, want)
	}
	if !s.sandboxInUse[got] {
		t.Fatalf("picked VMID %d was not marked reserved", got)
	}
}

// TestPickFreeSandboxVMID_NeverReturnsSameTwice is the C2 invariant: repeated picks
// (sequential, simulating non-overlapping reservation) never hand out the same
// VMID while a previous one is still reserved.
func TestPickFreeSandboxVMID_NeverReturnsSameTwice(t *testing.T) {
	s := newTestBackupService()
	// Everything absent on Proxmox: only the in-process reservation gates uniqueness.
	ping := func(int) (string, error) { return "absent", nil }

	seen := make(map[int]bool)
	total := sandboxVMIDMax - sandboxVMIDMin + 1
	for i := 0; i < total; i++ {
		vmid, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
		if err != nil {
			t.Fatalf("pick %d errored unexpectedly: %v", i, err)
		}
		if seen[vmid] {
			t.Fatalf("VMID %d handed out twice while still reserved", vmid)
		}
		seen[vmid] = true
		if vmid < sandboxVMIDMin || vmid > sandboxVMIDMax {
			t.Fatalf("VMID %d out of sandbox range", vmid)
		}
	}
	// Range is now fully reserved → the next pick must fail.
	if _, err := s.pickFreeSandboxVMIDWith(ping, noopLogf); err == nil {
		t.Fatalf("expected exhaustion error once all %d slots reserved", total)
	}
}

// TestPickFreeSandboxVMID_Concurrent stresses the atomic reservation under real
// goroutines: N concurrent pickers must each get a DISTINCT VMID (run with -race).
func TestPickFreeSandboxVMID_Concurrent(t *testing.T) {
	s := newTestBackupService()
	ping := func(int) (string, error) { return "absent", nil }

	const workers = 50
	var wg sync.WaitGroup
	results := make([]int, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			vmid, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
			results[idx] = vmid
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	seen := make(map[int]bool)
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d errored: %v", i, errs[i])
		}
		if seen[results[i]] {
			t.Fatalf("VMID %d handed out to two concurrent workers", results[i])
		}
		seen[results[i]] = true
	}
}

// TestReleaseSandboxVMID verifies a released slot becomes pickable again.
func TestReleaseSandboxVMID(t *testing.T) {
	s := newTestBackupService()
	ping := func(int) (string, error) { return "absent", nil }

	first, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
	if err != nil {
		t.Fatalf("first pick errored: %v", err)
	}
	s.releaseSandboxVMID(first)
	if s.sandboxInUse[first] {
		t.Fatalf("VMID %d still reserved after release", first)
	}
	// A fresh picker over a now-empty map must be able to take the same first slot.
	again, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
	if err != nil {
		t.Fatalf("second pick errored: %v", err)
	}
	if again != first {
		t.Fatalf("after release, expected to re-pick %d, got %d", first, again)
	}
}

// TestReconcileSandboxGuests_OnlyTouchesSandboxRange asserts the boot reconciliation
// only ever asks to destroy guests inside [9500,9599]. Production VMIDs in the list
// must be left strictly untouched.
func TestReconcileSandboxGuests_OnlyTouchesSandboxRange(t *testing.T) {
	s := newTestBackupService()

	vms := []models.VM{
		{ID: 100, Type: "VM"},  // production — must be ignored
		{ID: 110, Type: "CT"},  // production — must be ignored
		{ID: 9500, Type: "CT"}, // sandbox lower bound
		{ID: 9550, Type: "VM"}, // sandbox mid
		{ID: 9599, Type: "VM"}, // sandbox upper bound
		{ID: 9600, Type: "VM"}, // just above range — must be ignored
		{ID: 9499, Type: "VM"}, // just below range — must be ignored
	}

	var destroyed []int
	destroy := func(vmid int, pveType string) error {
		if !isSandboxVMID(vmid) {
			t.Fatalf("destroy called on NON-sandbox VMID %d (type %s) — safety breach", vmid, pveType)
		}
		destroyed = append(destroyed, vmid)
		return nil
	}

	cleaned := s.reconcileSandboxGuests(vms, destroy)

	wantDestroyed := map[int]bool{9500: true, 9550: true, 9599: true}
	if cleaned != len(wantDestroyed) {
		t.Fatalf("cleaned = %d, want %d", cleaned, len(wantDestroyed))
	}
	for _, v := range destroyed {
		if !wantDestroyed[v] {
			t.Fatalf("destroyed unexpected VMID %d", v)
		}
		delete(wantDestroyed, v)
	}
	if len(wantDestroyed) != 0 {
		t.Fatalf("expected sandbox VMIDs were not destroyed: %v", wantDestroyed)
	}
}

// TestReconcileSandboxGuests_CountsOnlySuccesses verifies that a destroy failure is
// not counted as cleaned (and does not abort the rest of the sweep).
func TestReconcileSandboxGuests_CountsOnlySuccesses(t *testing.T) {
	s := newTestBackupService() // discord nil → notifyZombieSandbox is a no-op

	vms := []models.VM{
		{ID: 9500, Type: "VM"},
		{ID: 9501, Type: "VM"}, // this one will fail to destroy
		{ID: 9502, Type: "VM"},
	}

	destroy := func(vmid int, _ string) error {
		if vmid == 9501 {
			return fmt.Errorf("boom")
		}
		return nil
	}

	if cleaned := s.reconcileSandboxGuests(vms, destroy); cleaned != 2 {
		t.Fatalf("cleaned = %d, want 2 (the failed one must not count)", cleaned)
	}
}

// TestBuildSandboxNetN_MultipleInterfaces documents that buildSandboxNetN is applied
// per-interface (the C1 fix forces tag=99 on every netN, not just net0).
func TestBuildSandboxNetN_MultipleInterfaces(t *testing.T) {
	ifaces := map[string]string{
		"net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,tag=20",
		"net1": "virtio=AA:BB:CC:DD:EE:02,bridge=vmbr0,tag=30",
		"net2": "name=eth2,bridge=vmbr0", // no tag yet
	}
	want := map[string]string{
		"net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr1,tag=99",
		"net1": "virtio=AA:BB:CC:DD:EE:02,bridge=vmbr1,tag=99",
		"net2": "name=eth2,bridge=vmbr1,tag=99",
	}
	for key, cur := range ifaces {
		got := buildSandboxNetN(cur, "qemu", 99)
		if got != want[key] {
			t.Errorf("%s: buildSandboxNetN(%q) = %q, want %q", key, cur, got, want[key])
		}
	}
}

// TestIsNetKey verifies only real netN keys are treated as interfaces.
func TestIsNetKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"net0", true},
		{"net1", true},
		{"net12", true},
		{"net", false},
		{"netfoo", false},
		{"net0x", false},
		{"name", false},
		{"ethernet0", false},
		{"", false},
		{"NET0", false}, // case-sensitive: PVE keys are lowercase
	}
	for _, tc := range tests {
		if got := isNetKey(tc.key); got != tc.want {
			t.Errorf("isNetKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}
