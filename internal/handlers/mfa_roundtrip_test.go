package handlers

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"goacore/internal/services"
)

// mfaTestSSH builds a real SSHService whose AES key is derived exactly like the app
// does in production (DeriveSSHEncKey over the session secret). The MFA secret is
// encrypted/decrypted with this same EncryptData/DecryptData pair, so the test
// exercises the real crypto the login + verify handlers rely on — no DB, no HTTP.
func mfaTestSSH() *services.SSHService {
	key := DeriveSSHEncKey("mfa-roundtrip-session-secret")
	return services.NewSSHService(nil, key, "", "", "", "", false)
}

// TestMFA_SecretEncryptRoundTripAndValidate is the end-to-end MFA invariant that the
// handlers depend on but split across two files:
//
//   - HandleVerifyMFA stores EncryptData(secret) in the DB.
//   - HandleLogin reads it back, DecryptData()s it, then totp.Validate()s the code.
//
// This test reproduces that exact chain in-memory: generate a TOTP secret, encrypt it,
// decrypt it, and prove a code derived from the ORIGINAL secret still validates against
// the DECRYPTED one. If EncryptData/DecryptData were not a faithful round-trip, the
// decrypted secret would differ and every real login would reject a correct authenticator
// code — this test would catch that.
func TestMFA_SecretEncryptRoundTripAndValidate(t *testing.T) {
	ssh := mfaTestSSH()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "GoaCore", AccountName: "alice"})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	secret := key.Secret()

	enc, err := ssh.EncryptData(secret)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if enc == secret {
		t.Fatal("encrypted MFA secret equals plaintext — secret stored in the clear")
	}

	dec, err := ssh.DecryptData(enc)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if dec != secret {
		t.Fatalf("MFA secret did not survive the round-trip: got %q want %q", dec, secret)
	}

	// A code generated from the original secret must validate against the decrypted one
	// (this is what login does after decrypting the stored secret).
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !totp.Validate(code, dec) {
		t.Fatal("a valid TOTP code failed to validate against the decrypted secret")
	}
}

// TestMFA_InvalidCodeRejected: a wrong 6-digit code must be rejected by the same
// validation login uses. This is the negative arm that proves the validate step is a
// real gate, not a rubber stamp.
func TestMFA_InvalidCodeRejected(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "GoaCore", AccountName: "bob"})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	secret := key.Secret()

	now := time.Now()
	valid, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	// Build a wrong code that is invalid BY CONSTRUCTION. We start from the valid code,
	// then walk candidates (mod 1_000_000, preserving the 6-digit zero-padding) until we
	// find one that totp.Validate actually rejects for this secret at this instant. This
	// is deterministic — unlike a fixed digit-flip, it cannot accidentally land on a code
	// that Validate accepts (e.g. an adjacent-window code, accepted with skew=1).
	wrong := firstInvalidCode(t, valid, secret)
	if wrong == valid {
		t.Fatal("test bug: wrong code equals valid code")
	}
	if totp.Validate(wrong, secret) {
		t.Fatalf("an invalid TOTP code %q was accepted for secret-derived valid %q", wrong, valid)
	}
	// Sanity: the valid one is still accepted (guards against a clock-skew flake making
	// the negative pass trivially because *everything* fails).
	if !totp.Validate(valid, secret) {
		t.Fatal("the freshly generated valid code did not validate — clock skew test bug")
	}
}

// TestMFA_CodeForDifferentSecretRejected: a code minted from a DIFFERENT secret must
// not validate — this is the property that makes the per-user secret meaningful (a
// leaked code for user A cannot authenticate user B).
func TestMFA_CodeForDifferentSecretRejected(t *testing.T) {
	a, _ := totp.Generate(totp.GenerateOpts{Issuer: "GoaCore", AccountName: "a"})
	b, _ := totp.Generate(totp.GenerateOpts{Issuer: "GoaCore", AccountName: "b"})
	if a.Secret() == b.Secret() {
		t.Fatal("two generated secrets collided — cannot test cross-secret rejection")
	}
	now := time.Now()
	codeForA, err := totp.GenerateCode(a.Secret(), now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if totp.Validate(codeForA, b.Secret()) {
		t.Fatal("a code generated for secret A validated against secret B")
	}
}

// TestMFA_DecryptLegacyPlaintextSecretFails documents the login fallback: HandleLogin
// tries DecryptData and, on error, keeps the raw stored string (legacy plaintext
// secret). Here we assert DecryptData refuses a value that is not our ciphertext, so
// the handler's "if decrypted, err := …; err == nil" branch correctly falls through to
// treating the stored value as already-plaintext. A non-erroring decrypt of garbage
// would silently corrupt the secret and break legacy logins.
func TestMFA_DecryptLegacyPlaintextSecretFails(t *testing.T) {
	ssh := mfaTestSSH()
	// A bare base32 TOTP secret is not valid AES-GCM ciphertext for our key.
	if _, err := ssh.DecryptData("JBSWY3DPEHPK3PXP"); err == nil {
		t.Fatal("DecryptData accepted a legacy plaintext secret as ciphertext; login fallback would be skipped")
	}
}

// firstInvalidCode returns a 6-digit TOTP code that totp.Validate REJECTS for the given
// secret right now. It starts one past the valid code and scans the entire 6-digit space
// (wrapping mod 1_000_000), returning the first candidate Validate refuses. Because it
// asks Validate directly, the result is invalid by construction regardless of clock skew
// or the ±1 window tolerance. The full space has exactly one (occasionally a few for
// skew) acceptable codes, so a rejecting candidate is found on the first or second try;
// scanning the whole space only guarantees termination.
func firstInvalidCode(t *testing.T, valid, secret string) string {
	t.Helper()
	start, err := strconv.Atoi(valid)
	if err != nil {
		t.Fatalf("valid code %q is not numeric: %v", valid, err)
	}
	for i := 1; i <= 1_000_000; i++ {
		candidate := fmt.Sprintf("%06d", (start+i)%1_000_000)
		if !totp.Validate(candidate, secret) {
			return candidate
		}
	}
	t.Fatal("no invalid 6-digit code found — every code validates, which is impossible")
	return ""
}
