// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const stateSchemaToken = "{{state}}"

// database bounds PostgreSQL connection acquisition and statement execution.
type database struct {
	raw        *sql.DB
	timeout    time.Duration
	postgresql bool
}

// stateSQL resolves explicit state-schema tokens for the configured database.
func (d *database) stateSQL(query string) string {
	schema := ""
	if d.postgresql {
		schema = "public."
	}
	return strings.ReplaceAll(query, stateSchemaToken, schema)
}

// queryContext creates the context used by one database operation.
func (d *database) queryContext() (context.Context, context.CancelFunc) {
	return d.operationContext(context.Background())
}

// operationContext applies the configured bound while preserving parent cancellation.
func (d *database) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if d.timeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d.timeout)
}

// Exec executes a statement with the configured bound.
func (d *database) Exec(query string, args ...any) (sql.Result, error) {
	ctx, cancel := d.queryContext()
	defer cancel()
	return d.raw.ExecContext(ctx, d.stateSQL(query), args...)
}

// ExecContext executes a statement with a caller-owned context.
func (d *database) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	ctx, cancel := d.operationContext(ctx)
	defer cancel()
	return d.raw.ExecContext(ctx, d.stateSQL(query), args...)
}

// Query starts a query whose context remains valid until its rows are closed.
func (d *database) Query(query string, args ...any) (*rows, error) {
	ctx, cancel := d.queryContext()
	r, err := d.raw.QueryContext(ctx, d.stateSQL(query), args...)
	if err != nil {
		cancel()
		return nil, err
	}
	return &rows{Rows: r, cancel: cancel}, nil
}

// QueryRow starts a query whose context remains valid through Scan.
func (d *database) QueryRow(query string, args ...any) *row {
	ctx, cancel := d.queryContext()
	return &row{Row: d.raw.QueryRowContext(ctx, d.stateSQL(query), args...), cancel: cancel}
}

// QueryRowContext delegates a caller-owned bounded query.
func (d *database) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.raw.QueryRowContext(ctx, d.stateSQL(query), args...)
}

// Begin starts a transaction and retains its timeout through commit or rollback.
func (d *database) Begin() (*transaction, error) {
	ctx, cancel := d.queryContext()
	tx, err := d.raw.BeginTx(ctx, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	return &transaction{Tx: tx, ctx: ctx, cancel: cancel, database: d}, nil
}

// PingContext checks connectivity with a caller-owned context.
func (d *database) PingContext(ctx context.Context) error { return d.raw.PingContext(ctx) }

// Close closes the underlying pool.
func (d *database) Close() error { return d.raw.Close() }

// Conn acquires a dedicated connection for integration tests and diagnostics.
func (d *database) Conn(ctx context.Context) (*sql.Conn, error) { return d.raw.Conn(ctx) }

// row releases its operation context after Scan returns.
type row struct {
	*sql.Row
	cancel context.CancelFunc
}

// Scan copies a row and releases its operation context.
func (r *row) Scan(dest ...any) error {
	defer r.cancel()
	return r.Row.Scan(dest...)
}

// rows releases its operation context after Close or a terminal error.
type rows struct {
	*sql.Rows
	cancel context.CancelFunc
}

// Close closes rows and releases its operation context.
func (r *rows) Close() error {
	err := r.Rows.Close()
	r.cancel()
	return err
}

// Err reports iteration errors and releases the context after a terminal result.
func (r *rows) Err() error {
	err := r.Rows.Err()
	r.cancel()
	return err
}

// transaction retains a bounded context for its complete lifetime.
type transaction struct {
	*sql.Tx
	ctx      context.Context
	cancel   context.CancelFunc
	database *database
}

// Exec executes a statement within the transaction context.
func (t *transaction) Exec(query string, args ...any) (sql.Result, error) {
	return t.ExecContext(t.ctx, t.database.stateSQL(query), args...)
}

// QueryRow starts a row query within the transaction context.
func (t *transaction) QueryRow(query string, args ...any) *sql.Row {
	return t.QueryRowContext(t.ctx, t.database.stateSQL(query), args...)
}

// Commit commits and releases the transaction context.
func (t *transaction) Commit() error {
	defer t.cancel()
	return t.Tx.Commit()
}

// Rollback rolls back and releases the transaction context.
func (t *transaction) Rollback() error {
	defer t.cancel()
	return t.Tx.Rollback()
}
