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
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.clients(id text primary key); CREATE TABLE `+schema+`.users(client_id text, subject text, groups text[]); CREATE TABLE `+schema+`.trust(client_id text, issuer_id text, binding_id text, subject text, required_claims jsonb, policy_claims jsonb, binding_claims jsonb, groups text[]); INSERT INTO `+schema+`.clients VALUES ('client'); INSERT INTO `+schema+`.users VALUES ('client','user@example.com',ARRAY['b','a']); INSERT INTO `+schema+`.trust VALUES ('client','issuer','binding','trusted:subject','{}','{}','{"sequence":{"const":9007199254740993}}',ARRAY['group']);`); err != nil {
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
		TrustBindings: `SELECT client_id,issuer_id,binding_id,subject,required_claims,policy_claims,binding_claims,groups FROM ` + schema + `.trust WHERE client_id=$1 AND issuer_id=$2`,
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
	bindings, err := r.ResolveTrust(ctx, "client", "issuer")
	if err != nil || len(bindings) != 1 || bindings[0].Subject != "trusted:subject" {
		t.Fatalf("bindings=%#v err=%v", bindings, err)
	}
	if err = bindings[0].Schema.Validate(map[string]any{"sequence": json.Number("9007199254740993")}); err != nil {
		t.Fatalf("large numeric const lost precision: %v", err)
	}
	if _, err = admin.Exec(ctx, `DELETE FROM `+schema+`.trust WHERE binding_id='binding'`); err != nil {
		t.Fatal(err)
	}
	if bindings, err = r.ResolveTrust(ctx, "client", "issuer"); err != nil || len(bindings) != 0 {
		t.Fatalf("removed binding was retained: bindings=%#v error=%v", bindings, err)
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
			_, queryErr = bad.ResolveTrust(ctx, "client", "issuer")
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
	_, err = framed.ResolveTrust(ctx, "client", "issuer")
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
