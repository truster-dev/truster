// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const schemaVersion = 2

// NewPostgreSQL opens a migrated PostgreSQL state database and verifies its compatibility.
func NewPostgreSQL(ctx context.Context, connectionString string, maxConnections int, queryTimeout time.Duration, logger *slog.Logger) (*Store, error) {
	if queryTimeout <= 0 {
		return nil, fmt.Errorf("PostgreSQL state database query timeout must be positive")
	}
	if err := validatePostgreSQLTLS(connectionString); err != nil {
		return nil, err
	}
	connConfig, err := pgx.ParseConfig(connectionString)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL state database connection string: %w", err)
	}
	connConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	db := stdlib.OpenDB(*connConfig)
	db.SetMaxOpenConns(maxConnections)
	db.SetMaxIdleConns(maxConnections)
	startup, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	if err = db.PingContext(startup); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect PostgreSQL state database: %w", err)
	}
	if err = CheckRuntime(startup, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s := &Store{db: &database{raw: db, timeout: queryTimeout, postgresql: true}, logger: logger, postgresql: true, cancel: cleanupCancel, cleanupCtx: cleanupCtx, done: make(chan struct{})}
	go s.cleanupExpired(cleanupCtx)
	return s, nil
}

// validatePostgreSQLTLS rejects plaintext connections except to loopback hosts.
func validatePostgreSQLTLS(connectionString string) error {
	u, err := url.Parse(connectionString)
	if err != nil {
		return fmt.Errorf("parse state database connection string: %w", err)
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	sslmode := u.Query().Get("sslmode")
	if !loopback && (sslmode == "" || sslmode == "disable" || sslmode == "allow" || sslmode == "prefer") {
		return fmt.Errorf("state database TLS is required except for loopback hosts")
	}
	return nil
}

// CheckSchema refuses absent, dirty, newer, or older PostgreSQL schemas.
func CheckSchema(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	var version int
	var dirty bool
	if err := db.QueryRowContext(ctx, `SELECT version,dirty FROM public.schema_migrations LIMIT 1`).Scan(&version, &dirty); err != nil {
		return fmt.Errorf("check state database schema: %w", err)
	}
	if dirty {
		return fmt.Errorf("state database schema version %d is dirty", version)
	}
	if version != schemaVersion {
		return fmt.Errorf("state database schema version %d is incompatible with supported version %d", version, schemaVersion)
	}
	return nil
}

// CheckRuntime verifies schema compatibility and the runtime role's state-table privileges.
func CheckRuntime(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	if err := CheckSchema(ctx, db); err != nil {
		return err
	}
	var allowed bool
	err := db.QueryRowContext(ctx, `SELECT has_schema_privilege(current_user,'public','USAGE')
		AND COALESCE(bool_and(
			has_table_privilege(current_user,format('%I.%I',schemaname,tablename),'SELECT')
			AND has_table_privilege(current_user,format('%I.%I',schemaname,tablename),'INSERT')
			AND has_table_privilege(current_user,format('%I.%I',schemaname,tablename),'UPDATE')
			AND has_table_privilege(current_user,format('%I.%I',schemaname,tablename),'DELETE')
		),false)
		FROM pg_catalog.pg_tables WHERE schemaname='public' AND tablename<>'schema_migrations'`).Scan(&allowed)
	if err != nil {
		return fmt.Errorf("check state database runtime privileges: %w", err)
	}
	if !allowed {
		return fmt.Errorf("state database runtime privileges are incomplete")
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.oauth_states WHERE false`).Scan(&count); err != nil {
		return fmt.Errorf("check state database runtime schema: %w", err)
	}
	return nil
}
