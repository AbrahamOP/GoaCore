package handlers

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestDummyBcryptHash_IsValidAndCostly is the unit-level guard for HandleLogin's
// account-enumeration defense.
//
// When the supplied username does not exist, HandleLogin runs
//
//	bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
//
// purely to burn the SAME CPU time a real password verification would, so an attacker
// cannot tell "no such user" from "wrong password" by response timing. That defense is
// only real if dummyBcryptHash is a genuine, correctly-formatted bcrypt hash at a
// realistic cost — a malformed hash would make CompareHashAndPassword return instantly
// with an error, collapsing the timing-equalisation and re-opening the enumeration
// oracle. This test fails if someone ever replaces the constant with a placeholder.
func TestDummyBcryptHash_IsValidAndCostly(t *testing.T) {
	cost, err := bcrypt.Cost([]byte(dummyBcryptHash))
	if err != nil {
		t.Fatalf("dummyBcryptHash is not a valid bcrypt hash: %v — login timing defense is broken", err)
	}
	// The real signup path uses bcrypt.DefaultCost; the dummy must match it so the wasted
	// work equals a real verification. A materially cheaper dummy would shorten the
	// unknown-user path and leak existence by timing.
	if cost < bcrypt.DefaultCost {
		t.Fatalf("dummyBcryptHash cost = %d, want >= DefaultCost (%d) to equalise login timing", cost, bcrypt.DefaultCost)
	}
}

// TestDummyBcryptHash_ActuallyRunsAComparison proves the dummy compare does real work
// for ANY password: it must report a mismatch (never accidentally accept a password,
// and never short-circuit to a format error). If the constant were corrupted, this
// returns a *format* error instead of the mismatch error, which the assertion rejects.
func TestDummyBcryptHash_ActuallyRunsAComparison(t *testing.T) {
	for _, pw := range []string{"", "password", "hunter2", "a-very-long-password-string-aaaaaaaa"} {
		err := bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(pw))
		if err == nil {
			t.Fatalf("dummy hash unexpectedly MATCHED password %q — anti-enumeration constant is unsafe", pw)
		}
		if err != bcrypt.ErrMismatchedHashAndPassword {
			t.Fatalf("dummy compare for %q returned %v, want a clean mismatch (a format error means the constant is malformed and the compare did no costly work)", pw, err)
		}
	}
}

// NOTE on coverage gap (documented intentionally):
// The FULL HandleLogin anti-enumeration contract — that an unknown user and a wrong
// password produce the byte-identical "Identifiants invalides" page AND comparable
// latency — requires a *sql.DB (the handler does SELECT ... FROM users) plus the
// template set, the RateLimiter and the Registry. Per the Lot D rule "no new external
// dependency" we do not stand up a fake sql driver here just for this message-equality
// assertion (the router RBAC test already pays that cost for a different invariant).
// Instead we pin the single load-bearing primitive of the defense — that the dummy
// bcrypt hash is real and as costly as a live verification — which is the part that can
// silently rot. The identical-error-string behaviour is visible and stable in
// auth.go (both branches call h.renderError(w, "login.html", "Identifiants invalides")).
