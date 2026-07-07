package workers

import (
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Ces tests exercent la persistance anti-rejeu du SOAR contre une vraie base
// MySQL. Ils sont skippés si SOAR_TEST_DSN n'est pas fourni, pour ne pas exiger
// une base dans le pipeline `go test` par défaut.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SOAR_TEST_DSN")
	if dsn == "" {
		t.Skip("SOAR_TEST_DSN non défini — test d'intégration MySQL skippé")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// Schéma minimal (identique à Migrate) sur des tables jetables.
	for _, q := range []string{
		`DROP TABLE IF EXISTS soar_state`,
		`DROP TABLE IF EXISTS soar_alert_dedup`,
		`CREATE TABLE soar_state (k VARCHAR(64) PRIMARY KEY, v TEXT NOT NULL)`,
		`CREATE TABLE soar_alert_dedup (alert_key VARCHAR(191) PRIMARY KEY, seen_at BIGINT NOT NULL, INDEX idx_seen_at (seen_at))`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("schema %q: %v", q, err)
		}
	}
	return db
}

func TestSoarStateRoundTrip(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	// Clé absente → "" sans erreur.
	if v, err := loadSoarState(db, "last_alert_poll"); err != nil || v != "" {
		t.Fatalf("clé absente: v=%q err=%v", v, err)
	}
	// Écriture puis relecture.
	want := time.Now().UTC().Format(time.RFC3339)
	if err := saveSoarState(db, "last_alert_poll", want); err != nil {
		t.Fatalf("save: %v", err)
	}
	if v, _ := loadSoarState(db, "last_alert_poll"); v != want {
		t.Fatalf("relecture: got %q want %q", v, want)
	}
	// Upsert : une 2e écriture remplace, pas de doublon PK.
	want2 := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	if err := saveSoarState(db, "last_alert_poll", want2); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if v, _ := loadSoarState(db, "last_alert_poll"); v != want2 {
		t.Fatalf("upsert relecture: got %q want %q", v, want2)
	}
}

func TestAlertDedupPersistAndRehydrate(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	// Persister deux clés, dont une en double (INSERT IGNORE ne doit pas planter).
	persistAlertDedup(db, "001:5402:2026-07-07T00:00:00")
	persistAlertDedup(db, "001:5402:2026-07-07T00:00:00") // doublon
	persistAlertDedup(db, "002:5715:2026-07-07T00:01:00")

	// Réhydratation dans une map neuve → les 2 clés distinctes sont présentes.
	m := &sync.Map{}
	if n := loadAlertDedup(db, m); n != 2 {
		t.Fatalf("rehydrate: got %d entries want 2", n)
	}
	if _, ok := m.Load("001:5402:2026-07-07T00:00:00"); !ok {
		t.Fatal("clé 1 absente après rehydrate")
	}
	if _, ok := m.Load("002:5715:2026-07-07T00:01:00"); !ok {
		t.Fatal("clé 2 absente après rehydrate")
	}
}

func TestAlertDedupRehydrateIgnoresOld(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	// Une entrée vieille de 3h (hors horizon 2h) ne doit pas être réhydratée.
	old := time.Now().Add(-3 * time.Hour).Unix()
	if _, err := db.Exec("INSERT INTO soar_alert_dedup (alert_key, seen_at) VALUES (?, ?)", "old:5402:x", old); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	persistAlertDedup(db, "fresh:5402:y") // récent

	m := &sync.Map{}
	n := loadAlertDedup(db, m)
	if n != 1 {
		t.Fatalf("rehydrate: got %d want 1 (seule l'entrée récente)", n)
	}
	if _, ok := m.Load("old:5402:x"); ok {
		t.Fatal("entrée périmée réhydratée à tort")
	}
}

// TestNilDBSafe garantit qu'un db nil ne provoque jamais de panic (parité des
// nil-guards demandée en revue).
func TestNilDBSafe(t *testing.T) {
	if v, err := loadSoarState(nil, "k"); v != "" || err != nil {
		t.Fatalf("loadSoarState(nil): %q %v", v, err)
	}
	if err := saveSoarState(nil, "k", "v"); err != nil {
		t.Fatalf("saveSoarState(nil): %v", err)
	}
	if n := loadAlertDedup(nil, &sync.Map{}); n != 0 {
		t.Fatalf("loadAlertDedup(nil): %d", n)
	}
	persistAlertDedup(nil, "k") // ne doit pas paniquer
}
