package router

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
	"goacore/internal/config"
	"goacore/internal/handlers"
	appMiddleware "goacore/internal/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fake in-process database/sql driver.
//
// The RBAC barrier (AuthMiddleware → AdminOnly → RequireAdmin) reads the role
// from the DB, NOT from the session: each runs `SELECT role FROM users WHERE
// username = ?`, and AuthMiddleware also runs `SELECT COUNT(*) FROM users`. To
// exercise the real router/middleware without a live MySQL — and WITHOUT adding
// any external dependency (no sqlmock) — we register a tiny driver built only on
// the stdlib `database/sql/driver`. It answers exactly those two queries from an
// in-memory role table, so the role a request "is" is whatever we seed here.
// ─────────────────────────────────────────────────────────────────────────────

// roleTable maps username → role for the fake driver. Guarded by a mutex because
// database/sql may dial connections from its own goroutines.
var (
	roleMu    sync.RWMutex
	roleTable = map[string]string{}
)

func setRole(username, role string) {
	roleMu.Lock()
	defer roleMu.Unlock()
	roleTable[username] = role
}

func lookupRole(username string) (string, bool) {
	roleMu.RLock()
	defer roleMu.RUnlock()
	r, ok := roleTable[username]
	return r, ok
}

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{}, nil }

type fakeConn struct{}

func (fakeConn) Prepare(query string) (driver.Stmt, error) { return fakeStmt{query: query}, nil }
func (fakeConn) Close() error                              { return nil }
func (fakeConn) Begin() (driver.Tx, error)                 { return nil, fmt.Errorf("no tx") }

type fakeStmt struct{ query string }

func (s fakeStmt) Close() error  { return nil }
func (s fakeStmt) NumInput() int { return -1 } // let database/sql skip arg-count checks

func (fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

func (s fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	q := normalize(s.query)
	switch {
	case strings.Contains(q, "select count(*) from users"):
		// AuthMiddleware: a nonzero count means "users exist" → don't redirect to /setup.
		return &fakeRows{cols: []string{"count"}, vals: [][]driver.Value{{int64(2)}}}, nil
	case strings.Contains(q, "select role from users where username"):
		username := ""
		if len(args) > 0 {
			if s, ok := args[0].(string); ok {
				username = s
			}
		}
		if role, ok := lookupRole(username); ok {
			return &fakeRows{cols: []string{"role"}, vals: [][]driver.Value{{role}}}, nil
		}
		// Unknown user → no rows, which Scan surfaces as sql.ErrNoRows. This is the
		// "user was deleted" path AuthMiddleware/AdminOnly treat as access-denied.
		return &fakeRows{cols: []string{"role"}, vals: nil}, nil
	default:
		// Any other query the real handlers might issue: return empty rows rather
		// than erroring, so an Admin request that slips past RBAC into a handler
		// fails on missing services (→ Recoverer 500), never on the DB layer — the
		// RBAC assertions below only care that it is NOT 403/login-redirect.
		return &fakeRows{cols: []string{}, vals: nil}, nil
	}
}

func normalize(q string) string {
	return strings.ToLower(strings.Join(strings.Fields(q), " "))
}

type fakeRows struct {
	cols []string
	vals [][]driver.Value
	pos  int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.pos])
	r.pos++
	return nil
}

var registerOnce sync.Once

func openFakeDB(t *testing.T) *sql.DB {
	t.Helper()
	registerOnce.Do(func() { sql.Register("rbacfake", fakeDriver{}) })
	db, err := sql.Open("rbacfake", "rbac")
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	return db
}

// ─────────────────────────────────────────────────────────────────────────────
// Test rig: the REAL router.New, wired with a minimal handler and the fake DB.
// ─────────────────────────────────────────────────────────────────────────────

const testSessionKey = "00000000000000000000000000000000" // 32 bytes, deterministic

func newTestStore() *sessions.CookieStore {
	return sessions.NewCookieStore([]byte(testSessionKey))
}

// newTestRouter builds the production router with a handler whose only populated
// fields are the ones the RBAC middleware and the router wiring touch. Proxmox is
// marked configured so the OnboardingGate is a no-op and never masks the RBAC
// result with a 303/409 of its own.
func newTestRouter(t *testing.T, store *sessions.CookieStore, db *sql.DB) http.Handler {
	t.Helper()
	cfg := &config.Config{
		// Non-empty triplet ⇒ ProxmoxConfigured() == true ⇒ gate is a no-op.
		ProxmoxURL:         "https://proxmox.example.test:8006",
		ProxmoxNode:        "node",
		ProxmoxTokenID:     "id",
		ProxmoxTokenSecret: "secret",
	}
	h := &handlers.Handler{
		DB:           db,
		SessionStore: store,
		Config:       cfg,
		ConfigStore:  config.NewConfigStore(cfg, nil),
	}
	if !h.ConfigStore.ProxmoxConfigured() {
		t.Fatal("test setup: ConfigStore should report Proxmox configured")
	}
	return New(h, store, db, false)
}

// sessionCookie produces a signed session cookie for the given username carrying
// authenticated=true and a known CSRF token, using the SAME CookieStore/key the
// router uses — so the request is indistinguishable from a real logged-in user.
func sessionCookie(t *testing.T, store *sessions.CookieStore, username, csrfToken string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	// store.New on a request with no existing cookie yields a fresh session.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, _ := store.New(req, "goacloud-session")
	sess.Values["authenticated"] = true
	sess.Values["username"] = username
	sess.Values["csrf_token"] = csrfToken
	if err := sess.Save(req, rec); err != nil {
		t.Fatalf("save session: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goacloud-session" {
			return c
		}
	}
	t.Fatal("no goacloud-session cookie produced")
	return nil
}

type route struct {
	method string
	path   string
}

// The sensitive routes are split into two groups by WHO actually enforces the 403 for a
// Viewer — so the test's guarantee is honest about its scope. The split was derived by
// reading each handler: a route is "router-only" iff its handler does NOT itself call
// middleware.RequireAdmin; it is "defense-in-depth" iff the handler ALSO re-checks
// RequireAdmin inline. (Both groups are wired inside the AdminOnly router group in
// router.go — that is not in question. What differs is what a green test PROVES.)
//
// routerOnlyDefended: the ONLY admin barrier for these is the AdminOnly router group.
// Their handlers contain no inline RequireAdmin, so if any of these were moved out of the
// AdminOnly group (into the authenticated/Viewer group), a Viewer would reach the handler
// and get a non-403 — turning the Viewer test RED. For THESE the assertion is a true
// "router guarantee": move it out of AdminOnly ⇒ test fails.
//
// These are the highest-value targets: a root SSH shell on guests, the SSH key manager,
// Ansible/playbook execution, Proxmox VM control (power/snapshots/console/create), the
// users/audit pages, and the onboarding pages that write infra credentials — all reachable
// by a Viewer the instant the router gate is removed, with nothing behind it.
var routerOnlyDefended = []route{
	// Root SSH shell on guests — the single worst Viewer→shell-root escalation.
	{http.MethodGet, "/console"},
	{http.MethodGet, "/api/ssh/ws"},

	// SSH key manager pages/endpoints served by HandleSSHManager (no inline check).
	{http.MethodGet, "/ssh"},
	{http.MethodPost, "/ssh"},
	{http.MethodGet, "/api/ssh/generate"},
	{http.MethodPost, "/api/ssh/generate"},

	// Ansible landing page (HandleAnsible — no inline check).
	{http.MethodGet, "/ansible"},

	// Proxmox state-changing / sensitive actions (power, snapshots, console, create) —
	// none of these handlers re-check the role, so the router group is their sole gate.
	{http.MethodPost, "/api/proxmox/guest/power"},
	{http.MethodPost, "/api/proxmox/snapshots"},
	{http.MethodDelete, "/api/proxmox/snapshots"},
	{http.MethodPost, "/api/proxmox/snapshots/rollback"},
	{http.MethodGet, "/api/proxmox/console"},
	{http.MethodPost, "/api/proxmox/guest/create"},

	// Onboarding pages with no inline RequireAdmin in the page handler.
	{http.MethodGet, "/onboarding/proxmox"},
	{http.MethodGet, "/onboarding/connexions"},

	// Paramètres hub — Admin-only sections. Their GET handlers have no inline
	// RequireAdmin, so the AdminOnly router group is their SOLE barrier: move any of
	// these into the authenticated group and a Viewer reaches the (services/users/
	// proxmox/canal) configuration surface, flipping this test red.
	{http.MethodGet, "/parametres/services"},
	{http.MethodGet, "/parametres/utilisateurs"},
	{http.MethodGet, "/parametres/proxmox"},
	{http.MethodGet, "/parametres/sauvegarde"},

	// SOAR outbound tests (HandleDiscordTest / HandleAITest — no inline check).
	{http.MethodPost, "/api/soar/discord/test"},
	{http.MethodPost, "/api/soar/ai/test"},

	// Backups page + user/audit pages (page handlers, no inline check).
	{http.MethodGet, "/backups"},
	{http.MethodGet, "/users"},
	{http.MethodGet, "/audit-logs"},
}

// defenseInDepth: these handlers ALSO call middleware.RequireAdmin inline. The AdminOnly
// router group AND the inline check each independently return 403 to a Viewer. So a green
// Viewer test here proves "the router gate OR the inline RequireAdmin denied the Viewer" —
// NOT specifically the router gate. Moving one of these out of AdminOnly would NOT turn the
// test red (the handler's own RequireAdmin still 403s). That is acceptable defence in depth,
// but the test must not over-claim a router guarantee for them.
var defenseInDepth = []route{
	// SSH deploy/delete (HandleSSHDeploy / HandleSSHDelete re-check inline).
	{http.MethodPost, "/api/ssh/deploy"},
	{http.MethodDelete, "/api/ssh/delete"},

	// Ansible execution + playbook + schedules (all re-check inline).
	{http.MethodPost, "/api/ansible/run"},
	{http.MethodPost, "/api/ansible/upload"},
	{http.MethodPut, "/api/ansible/playbook"},
	{http.MethodPost, "/api/ansible/schedules"},
	{http.MethodDelete, "/api/ansible/schedules"},
	{http.MethodPost, "/api/ansible/schedules/toggle"},

	// Onboarding write/test/delete APIs (each re-checks inline).
	{http.MethodPost, "/onboarding/proxmox"},
	{http.MethodPost, "/api/onboarding/proxmox/test"},
	{http.MethodPost, "/api/onboarding/proxmox/import-env"},
	{http.MethodPost, "/api/onboarding/proxmox/delete"},
	{http.MethodPost, "/onboarding/wazuh"},
	{http.MethodPost, "/api/onboarding/wazuh/test"},
	{http.MethodPost, "/onboarding/ai"},
	{http.MethodPost, "/api/onboarding/ai/delete"},
	{http.MethodPost, "/onboarding/discord"},
	{http.MethodGet, "/onboarding/canal"},
	{http.MethodPost, "/api/onboarding/canal/provision"},
	{http.MethodGet, "/api/onboarding/canal/installer.sh"},
	{http.MethodGet, "/api/onboarding/canal/helper.sh"},
	{http.MethodPost, "/api/onboarding/canal/delete"},

	// Backups create/test/settings (each re-checks inline).
	{http.MethodPost, "/api/backups/create"},
	{http.MethodPost, "/api/backups/test"},
	{http.MethodPost, "/api/backups/settings"},
	{http.MethodPost, "/api/backups/target-settings"},

	// SOAR config write (HandleSoarConfig re-checks inline on its POST arm).
	{http.MethodPost, "/api/soar/config"},

	// User management writes (add/delete/update re-check inline).
	{http.MethodPost, "/api/users/add"},
	{http.MethodPost, "/api/users/delete"},
	{http.MethodPost, "/api/users/update"},
}

// sensitiveRoutes is the union of both groups: every route below MUST 403 a Viewer,
// regardless of which layer enforces it. The Admin / unauthenticated tests iterate this
// union; the Viewer test runs both groups but documents the per-group guarantee.
var sensitiveRoutes = append(append([]route{}, routerOnlyDefended...), defenseInDepth...)

const csrfTok = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func doRequest(t *testing.T, router http.Handler, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	// Satisfy the global CSRF middleware on state-changing methods. The token here
	// MATCHES the one baked into the session cookie, so a CSRF rejection can never
	// be what masks the RBAC result we are actually asserting on.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.Header.Set("X-CSRF-Token", csrfTok)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestRBAC_ViewerDeniedOnSensitiveRoutes is the core invariant: every sensitive route
// rejects a logged-in Viewer with 403 and never lets the request reach its handler.
//
// It runs in two sub-groups whose guarantees differ — and the assertions are honest
// about that difference:
//
//   - routerOnly: the AdminOnly router group is the SOLE admin barrier (these handlers
//     have no inline RequireAdmin). For these, a 403 proves the ROUTER gate is doing the
//     work: move the route out of the AdminOnly group and a Viewer reaches the handler,
//     turning this test RED. This is a genuine router guarantee.
//
//   - defenseInDepth: the handler ALSO calls RequireAdmin inline, so a 403 here proves
//     only that "the router gate OR the inline RequireAdmin" denied the Viewer — not the
//     router gate specifically. Moving such a route out of AdminOnly would NOT turn this
//     test red (the inline check still 403s). The test still asserts the Viewer is denied
//     (the property we care about), it just does not claim to pin the router layer for it.
func TestRBAC_ViewerDeniedOnSensitiveRoutes(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("viewer", "Viewer")
	cookie := sessionCookie(t, store, "viewer", csrfTok)

	// routerOnly: a 403 here is a ROUTER guarantee — moving the route out of AdminOnly
	// makes a Viewer reach the (unguarded) handler, flipping this assertion to a failure.
	t.Run("routerOnly", func(t *testing.T) {
		for _, rt := range routerOnlyDefended {
			rt := rt
			t.Run(rt.method+" "+rt.path, func(t *testing.T) {
				rr := doRequest(t, router, rt.method, rt.path, cookie)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("Viewer on %s %s: got %d, want 403 — handler has no inline RequireAdmin, so this means the AdminOnly router gate is missing (Viewer reached the handler)",
						rt.method, rt.path, rr.Code)
				}
			})
		}
	})

	// defenseInDepth: a 403 here proves the router gate OR the handler's inline
	// RequireAdmin denied the Viewer — defence in depth, not a router-specific guarantee.
	t.Run("defenseInDepth", func(t *testing.T) {
		for _, rt := range defenseInDepth {
			rt := rt
			t.Run(rt.method+" "+rt.path, func(t *testing.T) {
				rr := doRequest(t, router, rt.method, rt.path, cookie)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("Viewer on %s %s: got %d, want 403 — neither the AdminOnly router gate NOR the inline RequireAdmin blocked the Viewer",
						rt.method, rt.path, rr.Code)
				}
			})
		}
	})
}

// TestRBAC_AdminPassesRBACOnSensitiveRoutes proves the routes are genuinely gated
// by the ROLE and not blanket-blocked: an Admin clears AuthMiddleware+AdminOnly on
// every sensitive route. We assert the response is NOT 403 and NOT a redirect to
// /login — i.e. RBAC let the request through to the handler (which may then 500 on
// the intentionally-nil services; that still proves the barrier opened for Admin).
// Without this counterpart, a middleware that 403'd EVERYONE would falsely satisfy
// the Viewer test, so this guards against an over-broad (and useless) gate.
func TestRBAC_AdminPassesRBACOnSensitiveRoutes(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("admin", "Admin")
	cookie := sessionCookie(t, store, "admin", csrfTok)

	for _, rt := range sensitiveRoutes {
		rt := rt
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rr := doRequest(t, router, rt.method, rt.path, cookie)
			if rr.Code == http.StatusForbidden {
				t.Fatalf("Admin on %s %s: got 403 — RBAC wrongly blocks an Admin (route not gated by ROLE)",
					rt.method, rt.path)
			}
			if rr.Code == http.StatusSeeOther {
				if loc := rr.Header().Get("Location"); loc == "/login" {
					t.Fatalf("Admin on %s %s: redirected to /login — Admin treated as unauthenticated",
						rt.method, rt.path)
				}
			}
		})
	}
}

// TestRBAC_UnauthenticatedRedirectedToLogin: an anonymous request to a sensitive route
// is blocked before reaching the handler. The blocking LAYER depends on the method, and
// the assertion is honest about that:
//
//   - GET (safe method): CSRF validation is skipped, so the request flows into
//     AuthMiddleware, which bounces the anonymous caller with 303→/login (or /setup when
//     no users exist). For GETs this test genuinely pins the AUTH redirect.
//
//   - POST/PUT/DELETE (state-changing): the global CSRF middleware runs BEFORE
//     AuthMiddleware. With no session cookie it mints a fresh token, our request carries a
//     non-matching header token, and CSRF returns 403 — so the request is rejected by CSRF
//     before auth is ever consulted. For these the "blocked" outcome is the CSRF 403, NOT
//     the auth redirect; both mean the handler never ran, which is what we assert.
//
// We therefore require GETs to redirect to /login (or /setup) and accept either a redirect
// or a CSRF 403 for non-GET methods.
func TestRBAC_UnauthenticatedRedirectedToLogin(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	isSafe := func(m string) bool { return m == http.MethodGet || m == http.MethodHead }

	for _, rt := range sensitiveRoutes {
		rt := rt
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rr := doRequest(t, router, rt.method, rt.path, nil)
			if rr.Code == http.StatusSeeOther {
				if loc := rr.Header().Get("Location"); loc != "/login" && loc != "/setup" {
					t.Fatalf("anon on %s %s: 303 to %q, want /login or /setup", rt.method, rt.path, loc)
				}
				return
			}
			if rr.Code == http.StatusForbidden {
				// A 403 is the CSRF block that fires before auth on state-changing methods.
				// For a safe GET, CSRF is skipped, so a 403 would mean something else blocked
				// it (or auth failed to redirect) — that is not the expected auth bounce.
				if isSafe(rt.method) {
					t.Fatalf("anon GET %s: got 403 (CSRF is skipped for safe methods) — expected a 303→/login auth redirect", rt.path)
				}
				return // CSRF block on a state-changing anon request — handler not reached.
			}
			t.Fatalf("anon on %s %s: got %d, expected to be blocked before the handler (303→/login for GET, 303 or CSRF 403 for non-GET)",
				rt.method, rt.path, rr.Code)
		})
	}
}

// TestRBAC_AdminOnlyMiddlewareDirect exercises the AdminOnly middleware in
// isolation (independent of the router wiring) to pin its contract: Admin → next
// runs; Viewer/empty/unknown → 403 and next NEVER runs.
func TestRBAC_AdminOnlyMiddlewareDirect(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)

	setRole("amid", "Admin")
	setRole("vmid", "Viewer")

	cases := []struct {
		name     string
		username string
		wantNext bool
		wantCode int
	}{
		{"admin passes", "amid", true, http.StatusOK},
		{"viewer blocked", "vmid", false, http.StatusForbidden},
		{"unknown user blocked", "ghost", false, http.StatusForbidden},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var nextRan bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextRan = true
				w.WriteHeader(http.StatusOK)
			})
			mw := appMiddleware.AdminOnly(store, db, next)

			cookie := sessionCookie(t, store, tc.username, csrfTok)
			req := httptest.NewRequest(http.MethodGet, "/api/users/add", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			mw.ServeHTTP(rr, req)

			if nextRan != tc.wantNext {
				t.Fatalf("%s: nextRan=%v want %v", tc.name, nextRan, tc.wantNext)
			}
			if rr.Code != tc.wantCode {
				t.Fatalf("%s: code=%d want %d", tc.name, rr.Code, tc.wantCode)
			}
		})
	}
}

// TestRBAC_RequireAdminInline pins the inline RequireAdmin helper used by handlers
// that double-check the role: it returns true only for Admin and writes 403+false
// for a Viewer or an unknown user. A regression that made it return true for a
// Viewer would silently re-open every handler relying on it.
func TestRBAC_RequireAdminInline(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)

	setRole("ra_admin", "Admin")
	setRole("ra_viewer", "Viewer")

	cases := []struct {
		name     string
		username string
		want     bool
		wantCode int
	}{
		{"admin", "ra_admin", true, http.StatusOK}, // no body written ⇒ recorder stays 200
		{"viewer", "ra_viewer", false, http.StatusForbidden},
		{"unknown", "ra_ghost", false, http.StatusForbidden},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cookie := sessionCookie(t, store, tc.username, csrfTok)
			req := httptest.NewRequest(http.MethodPost, "/api/users/add", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()

			got := appMiddleware.RequireAdmin(rr, req, store, db)
			if got != tc.want {
				t.Fatalf("%s: RequireAdmin=%v want %v", tc.name, got, tc.want)
			}
			if rr.Code != tc.wantCode {
				t.Fatalf("%s: code=%d want %d", tc.name, rr.Code, tc.wantCode)
			}
		})
	}
}

// TestRBAC_ViewerCanReachReadOnlySurface is the negative control for the Viewer
// test: a Viewer is NOT blanket-403'd — read-only routes in the authenticated
// group stay reachable (no 403). This ensures the Viewer-denial test above is
// detecting the ROLE gate specifically, not a global lockout. We only check the
// routes are not 403/login; the handlers may 500 on nil services.
func TestRBAC_ViewerCanReachReadOnlySurface(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("ro_viewer", "Viewer")
	cookie := sessionCookie(t, store, "ro_viewer", csrfTok)

	// Representative routes in the authenticated (non-admin) group a Viewer MUST be able
	// to reach: /api/me, plus the self-service Paramètres sections (profil, securite) and
	// the hub index. None carry AdminOnly; putting one behind it by mistake would lock a
	// Viewer out of their own profile/2FA — this control catches that regression.
	selfService := []string{"/api/me", "/parametres", "/parametres/profil", "/parametres/securite"}
	for _, path := range selfService {
		rr := doRequest(t, router, http.MethodGet, path, cookie)
		if rr.Code == http.StatusForbidden {
			t.Fatalf("Viewer on GET %s: got 403 — self-service surface wrongly gated as admin-only", path)
		}
		if rr.Code == http.StatusSeeOther && rr.Header().Get("Location") == "/login" {
			t.Fatalf("Viewer on GET %s: bounced to /login — authenticated Viewer treated as anon", path)
		}
	}
}

// ensure context import is used even if the stdlib trims it during refactors.
var _ = context.Background
