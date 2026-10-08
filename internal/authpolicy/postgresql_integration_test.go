// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/truster-dev/truster/v2/internal/config"
)

// TestPostgreSQLIntegration verifies production pgx startup, decoding, strict contracts, and failures.
func TestPostgreSQLIntegration(t *testing.T) {
	directURL := os.Getenv("TRUSTER_POLICY_TEST_DIRECT_DB_URL")
	if directURL == "" {
		t.Skip("TRUSTER_POLICY_TEST_DIRECT_DB_URL is not set")
	}
	pgBouncerURL := os.Getenv("TRUSTER_POLICY_TEST_PGBOUNCER_DB_URL")
	if pgBouncerURL == "" {
		pgBouncerURL = directURL
	}
	t.Log("TRUSTER_POLICY_TEST_DIRECT_DB_URL is set; running PostgreSQL integration coverage")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, directURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("auth_test_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.clients(id text primary key); CREATE TABLE `+schema+`.users(client_id text, subject text, groups text[]); CREATE TABLE `+schema+`.issuers(client_id text, issuer_id text, provider text, issuer_url text, signing_algs text[], max_token_age_seconds bigint); CREATE TABLE `+schema+`.trust(client_id text, issuer_id text, binding_id text, subject text, required_claims jsonb, policy_claims jsonb, binding_claims jsonb, groups text[]); INSERT INTO `+schema+`.clients VALUES ('client'); INSERT INTO `+schema+`.users VALUES ('client','user@example.com',ARRAY['b','a']); INSERT INTO `+schema+`.issuers VALUES ('client','dynamic','oidc','https://issuer.example',ARRAY['RS256'],600); INSERT INTO `+schema+`.trust VALUES ('client','issuer','binding','trusted:subject','{}','{}','{"sequence":{"const":9007199254740993}}',ARRAY['group']);`); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("auth_reader_%d", time.Now().UnixNano())
	roleSQL := pgx.Identifier{role}.Sanitize()
	if _, err = admin.Exec(ctx, `CREATE ROLE `+roleSQL+` LOGIN PASSWORD 'auth_test_reader'; GRANT USAGE ON SCHEMA `+schema+` TO `+roleSQL+`; GRANT SELECT ON ALL TABLES IN SCHEMA `+schema+` TO `+roleSQL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+roleSQL)
	})
	parsedRestrictedURL, err := neturl.Parse(pgBouncerURL)
	if err != nil {
		t.Fatal(err)
	}
	parsedRestrictedURL.User = neturl.UserPassword(role, "auth_test_reader")
	restrictedURL := parsedRestrictedURL.String()
	writeConfig, err := pgx.ParseConfig(restrictedURL)
	if err != nil {
		t.Fatal(err)
	}
	writeConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	writeProbe, err := pgx.ConnectConfig(ctx, writeConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writeProbe.Exec(ctx, `DELETE FROM `+schema+`.clients`); err == nil {
		_ = writeProbe.Close(ctx)
		t.Fatal("policy role unexpectedly modified policy data")
	}
	if err = writeProbe.Close(ctx); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.MaxConnections = 2
	cfg.Queries = config.PolicyQueries{
		ClientExists:  `SELECT EXISTS(SELECT 1 FROM ` + schema + `.clients WHERE id=$1) AS exists`,
		UserAccess:    `SELECT EXISTS(SELECT 1 FROM ` + schema + `.users WHERE client_id=$1 AND subject=$2) AS allowed, (SELECT groups FROM ` + schema + `.users WHERE client_id=$1 AND subject=$2) AS groups`,
		TrustIssuer:   `SELECT issuer_id,provider,issuer_url,signing_algs,max_token_age_seconds FROM ` + schema + `.issuers WHERE client_id=$1 AND issuer_url=$2`,
		TrustBindings: `SELECT client_id,issuer_id,binding_id,subject,required_claims,policy_claims,binding_claims,groups FROM ` + schema + `.trust WHERE client_id=$1 AND issuer_id=$2`,
	}
	t.Run("default queries", func(t *testing.T) {
		defaultSchema := schema + "_defaults"
		sql, readErr := os.ReadFile("../../examples/policy-db/postgresql.sql")
		if readErr != nil {
			t.Fatal(readErr)
		}
		// Isolate the example tables without requiring ownership of the real
		// truster_policy schema in the integration database.
		if _, err := admin.Exec(ctx, strings.ReplaceAll(string(sql), "truster_policy", defaultSchema)); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA `+defaultSchema+` CASCADE`) }()
		if _, err := admin.Exec(ctx, `INSERT INTO `+defaultSchema+`.clients VALUES ('client'); INSERT INTO `+defaultSchema+`.users VALUES ('client','user@example.com',ARRAY['developers']); INSERT INTO `+defaultSchema+`.trust_issuers VALUES ('client','custom','oidc','https://issuer.example',ARRAY['RS256'],600); INSERT INTO `+defaultSchema+`.trust_bindings VALUES ('client','custom','build','trusted:build','{}','{}','{"tenant":{"const":"acme"}}',ARRAY['builders']);`); err != nil {
			t.Fatal(err)
		}
		loaded, err := config.Load("../../examples/config/config-policy-db.jsonc")
		if err != nil {
			t.Fatal(err)
		}
		defaults := *loaded.PolicyDatabase
		for _, query := range []*string{&defaults.Queries.ClientExists, &defaults.Queries.UserAccess, &defaults.Queries.TrustIssuer, &defaults.Queries.TrustBindings} {
			*query = strings.ReplaceAll(*query, "truster_policy", defaultSchema)
		}
		resolver, err := NewPostgreSQL(ctx, directURL, defaults, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resolver.Close()
		if exists, err := resolver.ClientExists(ctx, "client"); err != nil || !exists {
			t.Fatalf("default client lookup exists=%v error=%v", exists, err)
		}
		if user, err := resolver.ResolveUser(ctx, "client", "USER@EXAMPLE.COM", true); err != nil || len(user.Groups) != 1 || user.Groups[0] != "developers" {
			t.Fatalf("default user lookup user=%#v error=%v", user, err)
		}
		if _, err := resolver.ResolveUser(ctx, "client", "unknown@example.com", false); !errors.Is(err, ErrDenied) {
			t.Fatalf("default unknown user error=%v, want denial", err)
		}
		id, issuer, err := resolver.ResolveTrustIssuer(ctx, "client", "https://issuer.example")
		if err != nil || id != "custom" || issuer.MaxTokenAge.Duration() != 10*time.Minute {
			t.Fatalf("default issuer id=%q config=%#v error=%v", id, issuer, err)
		}
		bindings, err := resolver.ResolveTrustBindings(ctx, "client", id, issuer)
		if err != nil || len(bindings) != 1 || bindings[0].Subject != "trusted:build" || bindings[0].Groups[0] != "builders" {
			t.Fatalf("default bindings=%#v error=%v", bindings, err)
		}
	})
	for _, name := range []string{"client_exists", "user_access", "trust_issuer", "trust_bindings", "all"} {
		t.Run("disabled "+name, func(t *testing.T) {
			disabled := cfg
			queries := map[string]*string{"client_exists": &disabled.Queries.ClientExists, "user_access": &disabled.Queries.UserAccess, "trust_issuer": &disabled.Queries.TrustIssuer, "trust_bindings": &disabled.Queries.TrustBindings}
			if name == "all" {
				disabled.Queries = config.PolicyQueries{}
			} else {
				*queries[name] = ""
			}
			resolver, err := NewPostgreSQL(ctx, restrictedURL, disabled, nil, nil)
			if err != nil {
				t.Fatalf("disabled-query startup: %v", err)
			}
			resolver.Close()
		})
	}
	r, err := NewPostgreSQL(ctx, restrictedURL, cfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if exists, e := r.ClientExists(ctx, "client"); e != nil || !exists {
		t.Fatalf("exists=%v err=%v", exists, e)
	}
	if user, e := r.ResolveUser(ctx, "client", "USER@EXAMPLE.COM", true); e != nil || len(user.Groups) != 2 || user.Groups[0] != "a" {
		t.Fatalf("user=%#v err=%v", user, e)
	}
	issuerID, issuer, err := r.ResolveTrustIssuer(ctx, "client", "https://issuer.example")
	if err != nil || issuerID != "dynamic" || issuer.MaxTokenAge.Duration() != 10*time.Minute {
		t.Fatalf("issuer_id=%q issuer=%#v err=%v", issuerID, issuer, err)
	}
	bindings, err := r.ResolveTrustBindings(ctx, "client", "issuer", r.issuers["issuer"])
	if err != nil || len(bindings) != 1 || bindings[0].Subject != "trusted:subject" {
		t.Fatalf("bindings=%#v err=%v", bindings, err)
	}
	if err = bindings[0].Schema.Validate(map[string]any{"sequence": json.Number("9007199254740993")}); err != nil {
		t.Fatalf("large numeric const lost precision: %v", err)
	}
	if _, err = admin.Exec(ctx, `DELETE FROM `+schema+`.trust WHERE binding_id='binding'`); err != nil {
		t.Fatal(err)
	}
	if bindings, err = r.ResolveTrustBindings(ctx, "client", "issuer", r.issuers["issuer"]); err != nil || len(bindings) != 0 {
		t.Fatalf("removed binding was retained: bindings=%#v error=%v", bindings, err)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO `+schema+`.trust VALUES ('client','dynamic','binding','trusted:dynamic','{}','{}','{"tenant":{"const":"acme"}}',ARRAY['builders'])`); err != nil {
		t.Fatal(err)
	}
	resolver := NewResolver(&config.Config{PolicyDatabase: &cfg}, r)
	client, err := resolver.ResolveClient(ctx, "client", true)
	if err != nil {
		t.Fatal(err)
	}
	resolvedIssuer, err := resolver.ResolveTrustIssuer(ctx, client, "https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	effective, err := resolver.ResolveTrustBindings(ctx, client, resolvedIssuer)
	if err != nil || len(effective) != 1 || effective[0].Subject != "trusted:dynamic" || effective[0].Groups[0] != "builders" {
		t.Fatalf("effective bindings=%#v error=%v", effective, err)
	}
	if err = effective[0].Schema.Validate(map[string]any{"tenant": "acme"}); err != nil {
		t.Fatalf("matching tenant rejected: %v", err)
	}
	if err = effective[0].Schema.Validate(map[string]any{"tenant": "other"}); err == nil {
		t.Fatal("unapproved tenant accepted")
	}
	if _, err = admin.Exec(ctx, `UPDATE `+schema+`.issuers SET max_token_age_seconds=120, signing_algs=ARRAY['ES256']`); err != nil {
		t.Fatal(err)
	}
	resolvedIssuer, err = resolver.ResolveTrustIssuer(ctx, client, "https://issuer.example")
	if err != nil || resolvedIssuer.Config.MaxTokenAge.Duration() != 2*time.Minute || resolvedIssuer.Config.SigningAlgs[0] != "ES256" {
		t.Fatalf("changed issuer=%#v error=%v", resolvedIssuer, err)
	}
	if _, err = admin.Exec(ctx, `DELETE FROM `+schema+`.issuers`); err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.ResolveTrustIssuer(ctx, client, "https://issuer.example"); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked issuer error=%v, want denial", err)
	}
	for name, test := range map[string]struct{ statement, want string }{
		"duplicate issuers":         {`SELECT 'dynamic'::text AS issuer_id,'oidc'::text AS provider,'https://issuer.example'::text AS issuer_url,ARRAY['RS256']::text[] AS signing_algs,600::bigint AS max_token_age_seconds FROM generate_series(1,2)`, "result row limit exceeded"},
		"null issuer URL":           {`SELECT 'dynamic'::text AS issuer_id,'oidc'::text AS provider,NULL::text AS issuer_url,ARRAY['RS256']::text[] AS signing_algs,600::bigint AS max_token_age_seconds`, "columns must be non-null"},
		"integer instead of bigint": {`SELECT 'dynamic'::text AS issuer_id,'oidc'::text AS provider,'https://issuer.example'::text AS issuer_url,ARRAY['RS256']::text[] AS signing_algs,600::integer AS max_token_age_seconds`, "unexpected column contract"},
		"null algorithm":            {`SELECT 'dynamic'::text AS issuer_id,'oidc'::text AS provider,'https://issuer.example'::text AS issuer_url,ARRAY['RS256',NULL]::text[] AS signing_algs,600::bigint AS max_token_age_seconds`, "null group element"},
		"oversized issuer URL":      {`SELECT 'dynamic'::text AS issuer_id,'oidc'::text AS provider,repeat('x',2049)::text AS issuer_url,ARRAY['RS256']::text[] AS signing_algs,600::bigint AS max_token_age_seconds`, "issuer URL exceeds limit"},
	} {
		badCfg := cfg
		badCfg.Queries.TrustIssuer = test.statement + ` WHERE $1::text='client' AND $2::text='https://issuer.example'`
		bad, openErr := NewPostgreSQL(ctx, restrictedURL, badCfg, nil, nil)
		if openErr != nil {
			t.Fatalf("%s setup: %v", name, openErr)
		}
		_, _, queryErr := bad.ResolveTrustIssuer(ctx, "client", "https://issuer.example")
		bad.Close()
		if !IsIndeterminate(queryErr) || !strings.Contains(queryErr.Error(), test.want) {
			t.Fatalf("%s error=%v, want indeterminate with %q", name, queryErr, test.want)
		}
	}
	if _, err = admin.Exec(ctx, `UPDATE `+schema+`.users SET groups=NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ResolveUser(ctx, "client", "user@example.com", false); !IsIndeterminate(err) {
		t.Fatalf("malformed type error=%v", err)
	}
	for name, statement := range map[string]string{"excess rows": `SELECT true AS exists FROM generate_series(1,2)`, "wrong type": `SELECT 1 AS exists`} {
		badCfg := cfg
		badCfg.Queries.ClientExists = statement
		bad, openErr := NewPostgreSQL(ctx, restrictedURL, badCfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil)
		if openErr != nil {
			t.Fatalf("%s setup: %v", name, openErr)
		}
		if _, queryErr := bad.clientExists(ctx, "uncached", false); !IsIndeterminate(queryErr) {
			t.Fatalf("%s error=%v", name, queryErr)
		}
		bad.Close()
	}
	partialCfg := cfg
	partialCfg.Queries.ClientExists = `SELECT CASE WHEN n=1 THEN true ELSE 1/(n-n)=0 END AS exists FROM generate_series(1,2) n WHERE $1::text IS NOT NULL`
	partial, err := NewPostgreSQL(ctx, restrictedURL, partialCfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, queryErr := partial.clientExists(ctx, "partial", false); !IsIndeterminate(queryErr) || !strings.Contains(queryErr.Error(), "division by zero") {
		t.Fatalf("partial result error=%v", queryErr)
	}
	partial.Close()
	for name, configure := range map[string]func(*config.PolicyDatabaseConfig){
		"excess user rows": func(c *config.PolicyDatabaseConfig) {
			c.Queries.UserAccess = `SELECT true AS allowed, ARRAY['group']::text[] AS groups FROM generate_series(1,2)`
		},
		"excess trust rows": func(c *config.PolicyDatabaseConfig) {
			c.MaxTrustRows = 1
			c.Queries.TrustBindings = `SELECT 'client'::text AS client_id,'issuer'::text AS issuer_id,('binding'||n)::text AS binding_id,'trusted:user'::text AS subject,'{}'::jsonb AS required_claims,'{}'::jsonb AS policy_claims,'{}'::jsonb AS binding_claims,ARRAY['group']::text[] AS groups FROM generate_series(1,2) n`
		},
		"aggregate trust JSON": func(c *config.PolicyDatabaseConfig) {
			c.MaxJSONBytes = 1024
			c.Queries.TrustBindings = `SELECT 'client'::text AS client_id,'issuer'::text AS issuer_id,('binding'||n)::text AS binding_id,'trusted:user'::text AS subject,jsonb_build_object('x',repeat('x',600)) AS required_claims,'{}'::jsonb AS policy_claims,'{}'::jsonb AS binding_claims,ARRAY['group']::text[] AS groups FROM generate_series(1,2) n`
		},
		"group cardinality": func(c *config.PolicyDatabaseConfig) {
			c.MaxGroups = 1
			c.Queries.UserAccess = `SELECT true AS allowed, ARRAY['one','two']::text[] AS groups`
		},
		"group bytes": func(c *config.PolicyDatabaseConfig) {
			c.MaxGroupBytes = 4
			c.Queries.UserAccess = `SELECT true AS allowed, ARRAY['12345']::text[] AS groups`
		},
	} {
		badCfg := cfg
		configure(&badCfg)
		bad, openErr := NewPostgreSQL(ctx, restrictedURL, badCfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil)
		if openErr != nil {
			t.Fatalf("%s setup: %v", name, openErr)
		}
		var queryErr error
		if name == "excess trust rows" || name == "aggregate trust JSON" {
			_, queryErr = bad.ResolveTrustBindings(ctx, "client", "issuer", bad.issuers["issuer"])
		} else {
			_, queryErr = bad.ResolveUser(ctx, "client", "user@example.com", false)
		}
		if !IsIndeterminate(queryErr) {
			t.Fatalf("%s error=%v", name, queryErr)
		}
		bad.Close()
	}
	frameCfg := cfg
	frameCfg.Queries.TrustBindings = fmt.Sprintf(`SELECT $1::text AS client_id,$2::text AS issuer_id,'binding'::text AS binding_id,repeat('x',%d)::text AS subject,'{}'::jsonb AS required_claims,'{}'::jsonb AS policy_claims,'{}'::jsonb AS binding_claims,ARRAY['group']::text[] AS groups`, backendMessageBodyLimit(frameCfg)+1)
	framed, err := NewPostgreSQL(ctx, restrictedURL, frameCfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = framed.ResolveTrustBindings(ctx, "client", "issuer", framed.issuers["issuer"])
	var bodyLimitErr *pgproto3.ExceededMaxBodyLenErr
	if !IsIndeterminate(err) || !errors.As(err, &bodyLimitErr) || bodyLimitErr.MaxExpectedBodyLen != backendMessageBodyLimit(frameCfg) || bodyLimitErr.ActualBodyLen <= bodyLimitErr.MaxExpectedBodyLen {
		t.Fatalf("oversized backend frame error=%v", err)
	}
	framed.Close()
	acquisitionCfg := cfg
	acquisitionCfg.MaxConnections = 1
	acquisitionCfg.QueryTimeout = config.Duration(500 * time.Millisecond)
	acquisitionCfg.Queries.ClientExists = `SELECT CASE WHEN $1::text='hold' THEN pg_sleep(1) IS NULL ELSE true END AS exists`
	exhausted, err := NewPostgreSQL(ctx, restrictedURL, acquisitionCfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	holder := make(chan error, 1)
	go func() {
		_, holdErr := exhausted.clientExists(context.Background(), "hold", false)
		holder <- holdErr
	}()
	for deadline := time.Now().Add(time.Second); ; {
		var active int
		if err = admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND state='active' AND query LIKE '%pg_sleep(1)%'`, role).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if active > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pool holder query did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	acquireCtx, acquireCancel := context.WithTimeout(ctx, 75*time.Millisecond)
	acquireStarted := time.Now()
	_, acquireErr := exhausted.clientExists(acquireCtx, "waiting", false)
	acquireCancel()
	if !IsIndeterminate(acquireErr) || !errors.Is(acquireErr, context.DeadlineExceeded) || time.Since(acquireStarted) >= 300*time.Millisecond {
		t.Fatalf("pool acquisition error=%v duration=%v", acquireErr, time.Since(acquireStarted))
	}
	if holdErr := <-holder; !IsIndeterminate(holdErr) {
		t.Fatalf("holder query error=%v", holdErr)
	}
	exhausted.Close()
	timeoutCfg := cfg
	timeoutCfg.QueryTimeout = config.Duration(100 * time.Millisecond)
	timeoutCfg.Queries.ClientExists = `SELECT pg_sleep(1) IS NULL AS exists WHERE $1::text IS NOT NULL`
	timed, err := NewPostgreSQL(ctx, restrictedURL, timeoutCfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = timed.clientExists(ctx, "timeout", false)
	elapsed := time.Since(started)
	if !IsIndeterminate(err) || elapsed < 50*time.Millisecond || elapsed >= time.Second {
		t.Fatalf("statement timeout error=%v duration=%v", err, elapsed)
	}
	timed.Close()
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err = r.clientExists(canceled, "uncached", false); !IsIndeterminate(err) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	r.Close()
	if _, err = r.clientExists(ctx, "outage", false); !IsIndeterminate(err) {
		t.Fatalf("closed pool error=%v", err)
	}
}
