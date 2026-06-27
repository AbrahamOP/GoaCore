package services

import (
	"strings"
	"testing"
)

func TestValidateSnapName(t *testing.T) {
	rejected := []string{"../../evil", "a/b", "name?x", "", "a b"}
	for _, name := range rejected {
		if err := validateSnapName(name); err == nil {
			t.Errorf("validateSnapName(%q) = nil, want error", name)
		}
	}

	accepted := []string{"daily", "pre-update_1", "snap.2026-06-25", "ABC123"}
	for _, name := range accepted {
		if err := validateSnapName(name); err != nil {
			t.Errorf("validateSnapName(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateVMID(t *testing.T) {
	rejected := []string{"abc", "../100", "0", "-5", ""}
	for _, vmid := range rejected {
		if err := validateVMID(vmid); err == nil {
			t.Errorf("validateVMID(%q) = nil, want error", vmid)
		}
	}

	if err := validateVMID("100"); err != nil {
		t.Errorf("validateVMID(%q) = %v, want nil", "100", err)
	}
}

// TestSnapshotOps_RejectMaliciousSnapName proves that a forged snapshot name is
// rejected by the in-method validation BEFORE any network call is attempted: the
// bogus URL (port 0) would otherwise produce a connection error rather than the
// "nom de snapshot invalide" message we assert on.
func TestSnapshotOps_RejectMaliciousSnapName(t *testing.T) {
	p := NewProxmoxService(nil, true)
	const badURL = "http://127.0.0.1:0"

	type opFn func(snapName string) error
	ops := map[string]opFn{
		"CreateSnapshot": func(snapName string) error {
			return p.CreateSnapshot(badURL, "pve", "tok", "sec", "qemu", "100", snapName, "desc")
		},
		"DeleteSnapshot": func(snapName string) error {
			return p.DeleteSnapshot(badURL, "pve", "tok", "sec", "qemu", "100", snapName)
		},
		"RollbackSnapshot": func(snapName string) error {
			return p.RollbackSnapshot(badURL, "pve", "tok", "sec", "qemu", "100", snapName)
		},
	}

	maliciousNames := []string{"../../evil", "a/b"}
	for opName, op := range ops {
		for _, snapName := range maliciousNames {
			err := op(snapName)
			if err == nil {
				t.Errorf("%s(%q) = nil, want error", opName, snapName)
				continue
			}
			if !strings.Contains(err.Error(), "nom de snapshot invalide") {
				t.Errorf("%s(%q) error = %q, want it to contain %q", opName, snapName, err.Error(), "nom de snapshot invalide")
			}
		}
	}
}
