package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

// csrfTestStore builds a CookieStore with a deterministic key. The CSRF middleware
// reads/writes the canonical "goacloud-session" cookie through this same store, so a
// test that forges (or replays) the cookie must use an identical store instance.
func csrfTestStore() *sessions.CookieStore {
	return sessions.NewCookieStore([]byte("csrf-test-session-key-0123456789abcdef"))
}

// primeSession drives one GET through a DEDICATED priming middleware (own store, no-op
// next) to let the CSRF middleware mint a token in the session, then returns the session
// cookie(s) it Set plus the token value baked into the readable _csrf cookie. Using a
// separate priming handler (not the test's own protected mw) keeps the priming GET from
// touching the test's "reached" flag — the token lives in the session cookie produced by
// the shared store, so it is fully valid for the test's mw on the subsequent POST. This
// mirrors what a real browser carries: the encrypted session cookie (authoritative
// token) plus the readable token the JS layer echoes back in the header/form.
func primeSession(t *testing.T, store *sessions.CookieStore) (cookies []*http.Cookie, token string) {
	t.Helper()
	prime := CSRFProtection(store, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	prime.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	cookies = res.Cookies()
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("priming GET did not set a readable _csrf cookie with a token")
	}
	return cookies, token
}

// attach copies a set of cookies onto a request (the browser->server replay leg).
func attach(req *http.Request, cookies []*http.Cookie) {
	for _, c := range cookies {
		req.AddCookie(c)
	}
}

// passThrough is the protected handler. It flips a flag if the request reached it,
// so a test can distinguish "middleware let it through" from "middleware blocked".
func passThrough(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

// TestCSRF_GETIsNeverBlocked: safe methods bypass token validation entirely and
// always reach the handler (the middleware only guards POST/PUT/DELETE).
func TestCSRF_GETIsNeverBlocked(t *testing.T) {
	store := csrfTestStore()
	reached := false
	mw := CSRFProtection(store, false)(passThrough(&reached))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	mw.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("GET was blocked by CSRF middleware; safe methods must pass")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
}

// TestCSRF_PostWithoutTokenRejected: the core invariant. A state-changing POST that
// carries the session cookie but NO token must be refused with 403 and must NOT reach
// the handler. If this protection is removed the handler would run -> test fails.
func TestCSRF_PostWithoutTokenRejected(t *testing.T) {
	store := csrfTestStore()
	reached := false
	mw := CSRFProtection(store, false)(passThrough(&reached))

	cookies, _ := primeSession(t, store)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users/add", nil)
	attach(req, cookies)
	mw.ServeHTTP(rec, req)

	if reached {
		t.Fatal("POST without CSRF token reached the handler — guard bypassed")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without token status = %d, want 403", rec.Code)
	}
}

// TestCSRF_PostWithInvalidTokenRejected: a token that does not match the one bound to
// the session is refused. Knowing the cookie is not enough — the value must match.
func TestCSRF_PostWithInvalidTokenRejected(t *testing.T) {
	store := csrfTestStore()
	reached := false
	mw := CSRFProtection(store, false)(passThrough(&reached))

	cookies, token := primeSession(t, store)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users/add", nil)
	attach(req, cookies)
	// Deliberately corrupt the token (flip nothing trivial — use a clearly wrong one
	// of the same length so we aren't merely tripping a length check).
	wrong := strings.Repeat("0", len(token))
	if wrong == token {
		wrong = strings.Repeat("1", len(token))
	}
	req.Header.Set(csrfHeaderName, wrong)
	mw.ServeHTTP(rec, req)

	if reached {
		t.Fatal("POST with an invalid CSRF token reached the handler — comparison too weak")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST with wrong token status = %d, want 403", rec.Code)
	}
}

// TestCSRF_PostWithValidHeaderTokenPasses: the matching token supplied via the
// X-CSRF-Token header lets the request through. This is the positive control that
// proves the rejections above are about the token, not a blanket POST lockout.
func TestCSRF_PostWithValidHeaderTokenPasses(t *testing.T) {
	store := csrfTestStore()
	reached := false
	mw := CSRFProtection(store, false)(passThrough(&reached))

	cookies, token := primeSession(t, store)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users/add", nil)
	attach(req, cookies)
	req.Header.Set(csrfHeaderName, token)
	mw.ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("POST with the valid header token was blocked (status %d) — false reject", rec.Code)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with valid token status = %d, want 200", rec.Code)
	}
}

// TestCSRF_PostWithValidFormTokenPasses: the token may also arrive in the
// urlencoded form field csrf_token (the classic <form> path), not only the header.
func TestCSRF_PostWithValidFormTokenPasses(t *testing.T) {
	store := csrfTestStore()
	reached := false
	mw := CSRFProtection(store, false)(passThrough(&reached))

	cookies, token := primeSession(t, store)

	form := url.Values{}
	form.Set(csrfFormField, token)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attach(req, cookies)
	mw.ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("POST with a valid form-field token was blocked (status %d)", rec.Code)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with valid form token status = %d, want 200", rec.Code)
	}
}

// TestCSRF_FormTokenIgnoredForJSONContentType: the form-field fallback only reads the
// token when the Content-Type is a form encoding. A JSON POST that smuggles the token
// in a body the middleware will not parse must still be rejected (it has to come via
// the header for JSON endpoints). This pins the exact content-type gating in the code.
//
// Note: this request also carries NO query string, so the rejection here is solely due
// to the content-type gating, not the (now-removed) query-param path. The dedicated
// TestCSRF_QueryParamTokenRejected below pins the query-string behaviour independently.
func TestCSRF_FormTokenIgnoredForJSONContentType(t *testing.T) {
	store := csrfTestStore()
	reached := false
	mw := CSRFProtection(store, false)(passThrough(&reached))

	cookies, token := primeSession(t, store)

	// Body is form-encoded text but the Content-Type says JSON, so FormValue is NOT
	// consulted and no header is set -> must 403.
	form := url.Values{}
	form.Set(csrfFormField, token)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/json")
	attach(req, cookies)
	mw.ServeHTTP(rec, req)

	if reached {
		t.Fatal("JSON POST with token only in an unparsed body reached the handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("JSON POST status = %d, want 403", rec.Code)
	}
}

// TestCSRF_QueryParamTokenRejected: the VALID token supplied only in the query string
// (?csrf_token=…) must NOT satisfy the guard. Accepting a token from the URL would be a
// latent CSRF surface — the secret would leak into access logs, the Referer header and
// browser history. The middleware accepts the token solely via the X-CSRF-Token header
// or the urlencoded/multipart form field; this test pins that the query-param path is
// closed. A regression that re-added the query fallback would let this POST through and
// flip the assertion.
func TestCSRF_QueryParamTokenRejected(t *testing.T) {
	store := csrfTestStore()
	reached := false
	mw := CSRFProtection(store, false)(passThrough(&reached))

	cookies, token := primeSession(t, store)

	rec := httptest.NewRecorder()
	// Correct, session-bound token — but placed ONLY in the query string. No header,
	// no form body. This must be refused.
	req := httptest.NewRequest(http.MethodPost, "/api/users/add?"+csrfFormField+"="+url.QueryEscape(token), nil)
	attach(req, cookies)
	mw.ServeHTTP(rec, req)

	if reached {
		t.Fatal("POST with the token only in the query string reached the handler — query-param CSRF fallback is open")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("query-param token POST status = %d, want 403", rec.Code)
	}
}

// TestCSRF_LoginAndSetupExemptFromValidation: /login and /setup are the bootstrap
// endpoints — there is no session yet to carry a token — so the middleware skips
// validation for them even on POST. Removing that carve-out would lock users out of
// authenticating; keeping it must NOT leak to any other path (covered by the rejects
// above, which all use non-exempt paths).
func TestCSRF_LoginAndSetupExemptFromValidation(t *testing.T) {
	store := csrfTestStore()
	for _, path := range []string{"/login", "/setup"} {
		reached := false
		mw := CSRFProtection(store, false)(passThrough(&reached))
		rec := httptest.NewRecorder()
		// No cookie, no token at all — still must pass for these bootstrap paths.
		req := httptest.NewRequest(http.MethodPost, path, nil)
		mw.ServeHTTP(rec, req)
		if !reached {
			t.Fatalf("POST %s was blocked; bootstrap endpoint must be exempt", path)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s status = %d, want 200", path, rec.Code)
		}
	}
}

// TestCSRF_PutAndDeleteAlsoGuarded: the guard is not POST-only; PUT and DELETE are
// equally state-changing and must be refused without a token.
func TestCSRF_PutAndDeleteAlsoGuarded(t *testing.T) {
	store := csrfTestStore()
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		reached := false
		mw := CSRFProtection(store, false)(passThrough(&reached))
		cookies, _ := primeSession(t, store)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/ssh/keys/1", nil)
		attach(req, cookies)
		mw.ServeHTTP(rec, req)
		if reached {
			t.Fatalf("%s without token reached the handler — only POST is guarded?", method)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s without token status = %d, want 403", method, rec.Code)
		}
	}
}

// TestCSRF_SecureCookieFlagHonored: when cookieSecure is true the readable _csrf
// cookie must carry Secure (so it is never sent over plain HTTP). This is a transport
// confidentiality property of the token cookie, asserted directly from the Set-Cookie.
func TestCSRF_SecureCookieFlagHonored(t *testing.T) {
	for _, secure := range []bool{true, false} {
		store := csrfTestStore()
		reached := false
		mw := CSRFProtection(store, secure)(passThrough(&reached))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		mw.ServeHTTP(rec, req)
		var got *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == csrfCookieName {
				got = c
			}
		}
		if got == nil {
			t.Fatalf("secure=%v: no _csrf cookie set", secure)
		}
		if got.Secure != secure {
			t.Errorf("secure=%v: _csrf cookie Secure=%v, want %v", secure, got.Secure, secure)
		}
		// The readable token cookie must stay non-HttpOnly so JS can echo it back.
		if got.HttpOnly {
			t.Errorf("secure=%v: _csrf cookie is HttpOnly; JS could not read the token", secure)
		}
	}
}
