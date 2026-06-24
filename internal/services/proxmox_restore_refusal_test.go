package services

import (
	"strings"
	"testing"
)

// outOfRangeVMIDs is the set of VMIDs that MUST be refused by every destructive
// restore-path method: both edges just outside the band, real production guests, and
// degenerate values. Anything here reaching a Proxmox call is a critical safety bug.
var outOfRangeVMIDs = []int{
	0,      // unset
	-1,     // negative
	100,    // OPNsense (prod VM)
	110,    // SRV-Docker (prod CT, the dashboard host itself)
	9499,   // one below the band
	9600,   // one above the band
	100000, // far out of range
}

// blackholeURL is an address no request can ever complete against. We point every
// destructive method at it so that IF the sandbox guard were missing, the method would
// fail with a connection/DNS error — a DIFFERENT, recognisable error than the sandbox
// refusal. The assertions below require the refusal message specifically, which can
// ONLY be produced by the in-process guard returning BEFORE any http.Client.Do. This
// is what proves the refusal happens with zero network egress.
const blackholeURL = "https://127.0.0.1:1/" // port 1, RST immediately if ever dialed

// assertSandboxRefusal fails unless err is the in-process sandbox refusal (no network
// reached). The refusal text is the stable contract from errNotSandbox.
func assertSandboxRefusal(t *testing.T, op string, vmid int, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s(vmid=%d) returned nil error — destructive op on a non-sandbox VMID was NOT refused", op, vmid)
	}
	msg := err.Error()
	if !strings.Contains(msg, "refus de sûreté") || !strings.Contains(msg, "hors de la plage sandbox") {
		t.Fatalf("%s(vmid=%d) error = %q; want the in-process sandbox refusal (a network/API error here means the guard ran AFTER a request, or not at all)", op, vmid, msg)
	}
}

// TestRestoreBackup_RefusesNonSandboxVMID: RestoreBackup must refuse every out-of-range
// VMID before issuing the restore POST. The blackhole URL guarantees a network attempt
// would surface as a connection error, so getting the sandbox refusal proves no request
// left the process.
func TestRestoreBackup_RefusesNonSandboxVMID(t *testing.T) {
	p := NewProxmoxService(nil, true)
	for _, vmid := range outOfRangeVMIDs {
		// storage="" intentionally: even the empty-storage defense-in-depth path must
		// not be reached, because the VMID guard precedes it.
		upid, err := p.RestoreBackup(blackholeURL, "node", "tok", "sec", "lxc",
			"local:backup/vzdump-lxc-110-2026.tar.zst", vmid, "")
		assertSandboxRefusal(t, "RestoreBackup", vmid, err)
		if upid != "" {
			t.Errorf("RestoreBackup(vmid=%d) returned a non-empty UPID %q on refusal", vmid, upid)
		}
	}
}

// TestSetGuestNetworkVlan_RefusesNonSandboxVMID: the network-isolation reconfigure must
// likewise refuse out-of-range VMIDs before reading/writing the guest config — forcing
// a VLAN onto a prod guest's NICs would be as dangerous as restoring over it.
func TestSetGuestNetworkVlan_RefusesNonSandboxVMID(t *testing.T) {
	p := NewProxmoxService(nil, true)
	for _, vmid := range outOfRangeVMIDs {
		err := p.SetGuestNetworkVlan(blackholeURL, "node", "tok", "sec", "lxc", vmid, 99, "vmbr1")
		assertSandboxRefusal(t, "SetGuestNetworkVlan", vmid, err)
	}
}

// TestDestroyGuest_RefusesNonSandboxVMID: the cleanup/purge call is the single most
// destructive operation (it deletes config + disks). It must refuse every out-of-range
// VMID before the force-stop or the DELETE. The blackhole URL again ensures any reached
// network attempt would NOT look like the sandbox refusal.
func TestDestroyGuest_RefusesNonSandboxVMID(t *testing.T) {
	p := NewProxmoxService(nil, true)
	for _, vmid := range outOfRangeVMIDs {
		upid, err := p.DestroyGuest(blackholeURL, "node", "tok", "sec", "lxc", vmid)
		assertSandboxRefusal(t, "DestroyGuest", vmid, err)
		if upid != "" {
			t.Errorf("DestroyGuest(vmid=%d) returned a non-empty UPID %q on refusal", vmid, upid)
		}
	}
}

// TestRestorePathMethods_AcceptSandboxVMID is the positive control proving the refusal
// is VMID-scoped, not a blanket failure: for an IN-range VMID the guard does NOT
// short-circuit, so the call proceeds to the network and fails with a NON-sandbox error
// (connection refused against the blackhole URL). If a sandbox VMID were also refused,
// the whole engine would be dead and the negative tests above would be vacuous.
//
// Only RestoreBackup is used here because it fails FAST on the connection-refused
// blackhole. SetGuestNetworkVlan returns nil on a failed config GET (no interfaces ⇒
// isolated), and DestroyGuest deliberately polls a stop deadline (~30s) — neither makes
// a crisp, fast positive control. The guard PLACEMENT for those two is already proven by
// their refusal tests above (an out-of-range VMID never reaches their network legs).
func TestRestorePathMethods_AcceptSandboxVMID(t *testing.T) {
	p := NewProxmoxService(nil, true)
	const inRange = 9550 // squarely inside [9500,9599]

	// MUST get past the guard and therefore fail with a non-refusal (connection) error.
	_, err := p.RestoreBackup(blackholeURL, "node", "tok", "sec", "lxc", "local:backup/x.tar.zst", inRange, "")
	assertProceededPastGuard(t, "RestoreBackup", err)
	if err == nil {
		t.Fatal("RestoreBackup against the blackhole unexpectedly succeeded — test cannot prove the guard was passed")
	}
}

// assertProceededPastGuard asserts the method got past the sandbox guard for an
// in-range VMID. It tolerates either a network error (the common case against the
// blackhole URL) or nil — what it must NOT be is the sandbox refusal, which would mean
// a valid sandbox VMID was wrongly rejected.
func assertProceededPastGuard(t *testing.T, op string, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "refus de sûreté") {
		t.Fatalf("%s refused an IN-range sandbox VMID (err=%q) — engine would be inoperative", op, err)
	}
}
