// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// postgreSQLStores opens two independent pools against the opt-in integration database.
func postgreSQLStores(t testing.TB) (*Store, *Store) {
	t.Helper()
	directDSN, pgBouncerDSN := postgreSQLTestURLs(t)
	if err := MigratePostgreSQL(directDSN); err != nil {
		t.Fatalf("migrate PostgreSQL: %v", err)
	}
	if err := MigratePostgreSQL(directDSN); err != nil {
		t.Fatalf("repeat PostgreSQL migration: %v", err)
	}
	if err := resetPostgreSQLState(directDSN); err != nil {
		t.Fatalf("reset PostgreSQL state: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := NewPostgreSQL(context.Background(), pgBouncerDSN, 8, 5*time.Second, logger)
	if err != nil {
		t.Fatalf("open first PostgreSQL pool: %v", err)
	}
	b, err := NewPostgreSQL(context.Background(), pgBouncerDSN, 8, 5*time.Second, logger)
	if err != nil {
		_ = a.Close()
		t.Fatalf("open second PostgreSQL pool: %v", err)
	}
	t.Cleanup(func() { _ = b.Close(); _ = a.Close() })
	return a, b
}

// postgreSQLTestURLs returns separate direct and optional PgBouncer endpoints.
func postgreSQLTestURLs(t testing.TB) (string, string) {
	t.Helper()
	directDSN := os.Getenv("TRUSTER_STATE_TEST_DIRECT_DB_URL")
	if directDSN == "" {
		t.Skip("TRUSTER_STATE_TEST_DIRECT_DB_URL is not set")
	}
	pgBouncerDSN := os.Getenv("TRUSTER_STATE_TEST_PGBOUNCER_DB_URL")
	if pgBouncerDSN == "" {
		pgBouncerDSN = directDSN
	}
	return directDSN, pgBouncerDSN
}

// resetPostgreSQLState removes state owned by prior integration-test runs.
func resetPostgreSQLState(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.Exec(`TRUNCATE truster_state.oauth_states,
		truster_state.auth_codes,
		truster_state.flow_credentials,
		truster_state.upstream_credentials,
		truster_state.otp_challenges,
		truster_state.otp_sends,
		truster_state.refresh_grants,
		truster_state.refresh_tokens,
		truster_state.grant_actions,
		truster_state.identity_selections,
		truster_state.pushed_requests CASCADE`); err != nil {
		return err
	}
	return tx.Commit()
}

// TestStateSchemaBinding verifies shared SQL retains its native numbered parameters.
func TestStateSchemaBinding(t *testing.T) {
	db := &database{postgresql: true}
	if got, want := db.stateSQL("SELECT $1 FROM {{state}}oauth_states"), "SELECT $1 FROM truster_state.oauth_states"; got != want {
		t.Fatalf("PostgreSQL state SQL = %q, want %q", got, want)
	}
	if got, want := (&database{}).stateSQL("SELECT $1 FROM {{state}}oauth_states"), "SELECT $1 FROM oauth_states"; got != want {
		t.Fatalf("SQLite state SQL = %q, want %q", got, want)
	}
}

// TestPostgreSQLCrossReplicaSemantics verifies single-use, replay, claim, and quota contracts across pools.
func TestPostgreSQLCrossReplicaSemantics(t *testing.T) {
	a, b := postgreSQLStores(t)
	now := time.Now().UTC()
	stateID, _ := GenerateStateToken()
	if err := a.SaveState(&OAuthState{StateToken: stateID, ClientID: "client", RedirectURI: "https://client.example", CodeChallenge: "challenge", OIDCState: "state", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Scopes: "openid", AuthTime: now}); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for _, store := range []*Store{a, b} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			if _, err := s.GetAndDeleteState(stateID); err == nil {
				winners.Add(1)
			}
		}(store)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("state race had %d winners", winners.Load())
	}

	current, _ := GenerateRefreshMaterial()
	replacementA, _ := GenerateRefreshMaterial()
	replacementB, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: stateID, ClientID: "client", Email: "user@example.com", EmailVerified: true, Scopes: "openid", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(24 * time.Hour)}
	if err := a.CreateRefreshGrant(grant, current, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for i, store := range []*Store{a, b} {
		replacement := replacementA
		if i == 1 {
			replacement = replacementB
		}
		wg.Add(1)
		go func(s *Store, next RefreshMaterial) {
			defer wg.Done()
			_, _, err := s.RotateRefreshToken(current, next, "client", now.Add(time.Second))
			errs <- err
		}(store, replacement)
	}
	wg.Wait()
	close(errs)
	winners.Store(0)
	var replay int
	for err := range errs {
		if err == nil {
			winners.Add(1)
		}
		if errors.Is(err, ErrRefreshReplay) {
			replay++
		}
	}
	if winners.Load() != 1 || replay != 1 {
		t.Fatalf("refresh race winners=%d replay=%d", winners.Load(), replay)
	}
	if _, _, err := a.PrepareRefresh(replacementA, "client", now.Add(2*time.Second)); !errors.Is(err, ErrInvalidGrant) {
		if _, _, otherErr := a.PrepareRefresh(replacementB, "client", now.Add(2*time.Second)); !errors.Is(otherErr, ErrInvalidGrant) {
			t.Fatalf("replacement survived replay revocation: %v / %v", err, otherErr)
		}
	}

	secret := []byte("01234567890123456789012345678901")
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := []*Store{a, b}[i%2].CreateOTP(stateID+string(rune('a'+i)), "Quota@Example.com", "12345678", OTPFlow{Email: "Quota@Example.com"}, secret, now, time.Minute)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	winners.Store(0)
	for err := range results {
		if err == nil {
			winners.Add(1)
		}
	}
	if winners.Load() != 5 {
		t.Fatalf("OTP quota admitted %d sends", winners.Load())
	}
}

// TestPostgreSQLGrantActionConsumeRace verifies batched actions remain single-use across replicas.
func TestPostgreSQLGrantActionConsumeRace(t *testing.T) {
	a, b := postgreSQLStores(t)
	now := time.Now().UTC()
	material, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "managed", ClientID: "client", Email: "user@example.com", Scopes: "openid", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err := a.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	actions := []GrantAction{{Token: "first", SID: grant.SID}, {Token: "second", SID: grant.SID}}
	if err := a.CreateGrantActions(actions, grant.Email, "revoke", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var actionCount int
	if err := a.db.QueryRow(`SELECT count(*) FROM {{state}}grant_actions WHERE sid=$1`, grant.SID).Scan(&actionCount); err != nil || actionCount != len(actions) {
		t.Fatalf("stored actions = %d, want %d: %v", actionCount, len(actions), err)
	}
	errs := make(chan error, 2)
	start := make(chan struct{})
	for _, store := range []*Store{a, b} {
		go func(s *Store) {
			<-start
			errs <- s.ConsumeGrantActionAndRevoke("first", grant.Email, grant.SID, "revoke", now)
		}(store)
	}
	close(start)
	var succeeded, rejected int
	for range 2 {
		if err := <-errs; err == nil {
			succeeded++
		} else if errors.Is(err, ErrInvalidGrant) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("grant action race succeeded=%d rejected=%d", succeeded, rejected)
	}
}

// TestPostgreSQLAuthorizationCodeConsumeRace verifies that independent replicas cannot consume one code twice.
func TestPostgreSQLAuthorizationCodeConsumeRace(t *testing.T) {
	a, b := postgreSQLStores(t)
	now := time.Now().UTC()
	code := AuthCode{Code: "cross-pool-code", ClientID: "client", RedirectURI: "https://client.example/cb", CodeChallenge: "challenge", Email: "user@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Scopes: "openid", RefreshMode: "", AuthTime: now}
	if err := a.SaveAuthCode(&code); err != nil {
		t.Fatal(err)
	}
	expected, err := a.PeekAuthCode(code.Code, now)
	if err != nil {
		t.Fatal(err)
	}
	binding := AuthCodeBinding{ClientID: code.ClientID, RedirectURI: code.RedirectURI, CodeChallenge: code.CodeChallenge}
	errs := make(chan error, 2)
	for _, store := range []*Store{a, b} {
		go func(s *Store) { errs <- s.ConsumeAuthCode(*expected, binding, nil, RefreshMaterial{}, now) }(store)
	}
	winners := 0
	for range 2 {
		if err := <-errs; err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("authorization code race had %d winners", winners)
	}
}

// TestPostgreSQLRefreshClaimContentionAndRelease verifies claim fencing and release across pools.
func TestPostgreSQLRefreshClaimContentionAndRelease(t *testing.T) {
	a, b := postgreSQLStores(t)
	now := time.Now().UTC()
	material, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "claim-cross-pool", ClientID: "client", Email: "user@example.com", Scopes: "openid", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(24 * time.Hour)}
	if err := a.CreateRefreshGrant(grant, material, []byte{1}, []byte{2}, now); err != nil {
		t.Fatal(err)
	}
	claimed, claim, _, err := a.ClaimRefresh(material, "client", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = b.ClaimRefresh(material, "client", now, time.Minute); !errors.Is(err, ErrRefreshBusy) {
		t.Fatalf("contending claim = %v", err)
	}
	if err = b.ReleaseRefreshClaim(claimed.SID, claim); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = b.ClaimRefresh(material, "client", now, time.Minute); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

// TestPostgreSQLSchemaRejection checks dirty and incompatible metadata without leaving it modified.
func TestPostgreSQLSchemaRejection(t *testing.T) {
	a, _ := postgreSQLStores(t)
	for _, tc := range []struct {
		name    string
		version int
		dirty   bool
	}{{"dirty", schemaVersion, true}, {"older", 0, false}, {"newer", schemaVersion + 1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := a.db.Exec(`UPDATE public.schema_migrations SET version=$1, dirty=$2`, tc.version, tc.dirty); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = a.db.Exec(`UPDATE public.schema_migrations SET version=$1, dirty=false`, schemaVersion) })
			if err := CheckSchema(context.Background(), a.db); err == nil {
				t.Fatal("incompatible schema was accepted")
			}
			if _, err := a.db.Exec(`UPDATE public.schema_migrations SET version=$1, dirty=false`, schemaVersion); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestPostgreSQLConcurrentNoOpMigrate verifies migration locking after the schema is current.
func TestPostgreSQLConcurrentNoOpMigrate(t *testing.T) {
	postgreSQLStores(t)
	dsn := os.Getenv("TRUSTER_STATE_TEST_DIRECT_DB_URL")
	errs := make(chan error, 8)
	for range 8 {
		go func() { errs <- MigratePostgreSQL(dsn) }()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent migration: %v", err)
		}
	}
}

// TestPostgreSQLPoolTimeoutAndReadiness verifies bounded waits when the only connection is exhausted.
func TestPostgreSQLPoolTimeoutAndReadiness(t *testing.T) {
	postgreSQLStores(t)
	_, dsn := postgreSQLTestURLs(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewPostgreSQL(context.Background(), dsn, 1, 50*time.Millisecond, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	conn, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	start := time.Now()
	if err = store.Ready(context.Background()); err == nil {
		t.Fatal("readiness succeeded with exhausted pool")
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("readiness timeout took %s", elapsed)
	}
	now := time.Now().UTC()
	state := &OAuthState{StateToken: "exhausted-pool-write", ClientID: "client", RedirectURI: "https://client.example", CodeChallenge: "challenge", OIDCState: "state", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Scopes: "openid", AuthTime: now}
	start = time.Now()
	if err = store.SaveState(state); err == nil {
		t.Fatal("mutating operation succeeded with exhausted pool")
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("mutating operation timeout took %s", elapsed)
	}
	start = time.Now()
	store.cleanupExpiredAt(now)
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("cleanup timeout took %s", elapsed)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Ready(context.Background()); err != nil {
		t.Fatalf("readiness after release: %v", err)
	}
	if err = store.db.QueryRow(`SELECT pg_sleep(1)`).Scan(new(any)); err == nil {
		t.Fatal("query exceeded context timeout")
	}
	closeStore, err := NewPostgreSQL(context.Background(), dsn, 1, 5*time.Second, logger)
	if err != nil {
		t.Fatal(err)
	}
	closeConn, err := closeStore.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cleanupDone := make(chan struct{})
	go func() {
		closeStore.cleanupExpiredAtContext(closeStore.cleanupCtx, now)
		close(cleanupDone)
	}()
	time.Sleep(50 * time.Millisecond)
	start = time.Now()
	if err = closeStore.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close waited %s for blocked cleanup", elapsed)
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not observe Close cancellation")
	}
	_ = closeConn.Close()
}

// TestPostgreSQLRuntimeIsSearchPathIndependent verifies state SQL without an application-owned session setting.
func TestPostgreSQLRuntimeIsSearchPathIndependent(t *testing.T) {
	postgreSQLStores(t)
	dsn, _ := postgreSQLTestURLs(t)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	parameters := u.Query()
	parameters.Set("search_path", "public")
	parameters.Set("application_name", "truster-guc-test")
	u.RawQuery = parameters.Encode()
	store, err := NewPostgreSQL(context.Background(), u.String(), 2, 50*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	var searchPath, applicationName string
	if err = store.db.QueryRow(`SELECT current_setting('search_path'),current_setting('application_name')`).Scan(&searchPath, &applicationName); err != nil {
		t.Fatal(err)
	}
	if searchPath != "public" || applicationName != "truster-guc-test" {
		t.Fatalf("runtime settings search_path=%q application_name=%q", searchPath, applicationName)
	}
	now := time.Now().UTC()
	if err = store.SaveState(&OAuthState{StateToken: "forced-search-path", ClientID: "client", RedirectURI: "https://client.example", CodeChallenge: "challenge", OIDCState: "state", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Scopes: "openid", AuthTime: now}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = store.db.QueryRow(`SELECT count(*) FROM truster_state.oauth_states WHERE state_token='forced-search-path'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("state schema write count=%d err=%v", count, err)
	}
	if err = store.db.QueryRow(`SELECT pg_sleep(1)`).Scan(new(any)); err == nil {
		t.Fatal("query exceeded context timeout")
	}
}

// TestPostgreSQLMigrationMetadataIsForcedPublic verifies conflicting migration parameters cannot relocate metadata.
func TestPostgreSQLMigrationMetadataIsForcedPublic(t *testing.T) {
	postgreSQLStores(t)
	dsn := os.Getenv("TRUSTER_STATE_TEST_DIRECT_DB_URL")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	parameters := u.Query()
	parameters.Set("search_path", "truster_state")
	parameters.Set("x-migrations-table", "schema_migrations_conflict")
	parameters.Set("x-migrations-table-quoted", "false")
	u.RawQuery = parameters.Encode()
	if err = MigratePostgreSQL(u.String()); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var publicCount, stateCount int
	if err = db.QueryRow(`SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='schema_migrations'`).Scan(&publicCount); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM pg_tables WHERE schemaname='truster_state' AND tablename LIKE 'schema_migrations%'`).Scan(&stateCount); err != nil {
		t.Fatal(err)
	}
	if publicCount != 1 || stateCount != 0 {
		t.Fatalf("migration metadata public=%d state=%d", publicCount, stateCount)
	}
}

// TestPostgreSQLRuntimeRequiresAllPrivileges verifies readiness rejects read-only state roles.
func TestPostgreSQLRuntimeRequiresAllPrivileges(t *testing.T) {
	a, _ := postgreSQLStores(t)
	const role = "truster_state_readiness_test"
	cleanup := func() {
		_, _ = a.db.raw.Exec(`DROP OWNED BY ` + role)
		_, _ = a.db.raw.Exec(`DROP ROLE IF EXISTS ` + role)
	}
	cleanup()
	t.Cleanup(cleanup)
	if _, err := a.db.raw.Exec(`CREATE ROLE ` + role + ` LOGIN PASSWORD 'readiness-test';
		GRANT USAGE ON SCHEMA public,truster_state TO ` + role + `;
		GRANT SELECT ON public.schema_migrations TO ` + role + `;
		GRANT SELECT ON ALL TABLES IN SCHEMA truster_state TO ` + role); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("TRUSTER_STATE_TEST_DIRECT_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "readiness-test")
	store, err := NewPostgreSQL(context.Background(), u.String(), 1, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		_ = store.Close()
		t.Fatal("read-only runtime role passed readiness")
	}
	if !strings.Contains(err.Error(), "runtime privileges are incomplete") {
		t.Fatalf("read-only runtime role failed for the wrong reason: %v", err)
	}
}

// TestPostgreSQLMigrationParameters verifies callers cannot disable bounded migration waits.
func TestPostgreSQLMigrationParameters(t *testing.T) {
	connectionString, err := migrationConnectionString("postgresql://localhost/state?connect_timeout=0&statement_timeout=0&x-statement-timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(connectionString)
	if err != nil {
		t.Fatal(err)
	}
	parameters := u.Query()
	if parameters.Get("connect_timeout") != "10" || parameters.Get("statement_timeout") != "300000" || parameters.Get("x-statement-timeout") != "300000" {
		t.Fatalf("unbounded migration parameters: %s", u.RawQuery)
	}
}

// TestPostgreSQLMigrationBaseline verifies v2.0.0 ships one complete initial migration.
func TestPostgreSQLMigrationBaseline(t *testing.T) {
	entries, err := migrations.ReadDir("migrations/postgresql")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "000001_initial.up.sql" {
		t.Fatalf("migration files = %v", entries)
	}
	baseline, err := migrations.ReadFile("migrations/postgresql/000001_initial.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	schema := string(baseline)
	for _, required := range []string{"CREATE TABLE oauth_states", "CREATE TABLE auth_codes", "CREATE TABLE refresh_grants", "CREATE TABLE pushed_requests", "pushed_authorization boolean", "dpop_jkt text"} {
		if !strings.Contains(schema, required) {
			t.Errorf("baseline migration is missing %q", required)
		}
	}
	if strings.Contains(schema, "dpop_proofs") {
		t.Fatal("baseline migration contains obsolete DPoP replay storage")
	}
}
