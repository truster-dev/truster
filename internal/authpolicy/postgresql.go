// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/truster-dev/truster/v2/internal/config"
	"golang.org/x/sync/singleflight"
)

// ErrDenied marks a definitive, well-formed policy denial.
var ErrDenied = errors.New("auth denied")

const maxBackendMessageBody = 64 << 20

// IndeterminateError marks a resolver or malformed-result failure that callers may retry.
type IndeterminateError struct{ Err error }

// Error returns a non-sensitive failure description.
func (e *IndeterminateError) Error() string {
	return "auth resolution indeterminate: " + e.Err.Error()
}

// Unwrap returns the underlying resolver error.
func (e *IndeterminateError) Unwrap() error { return e.Err }

// IsIndeterminate reports whether err is a retryable resolver failure.
func IsIndeterminate(err error) bool { var target *IndeterminateError; return errors.As(err, &target) }

// DynamicTrustRow is one strict trust_bindings query input.
type DynamicTrustRow struct {
	ClientID, IssuerID, BindingID, Subject      string
	RequiredClaims, PolicyClaims, BindingClaims map[string]json.RawMessage
	Groups                                      []string
}

// CompiledBinding combines current identity output with an immutable effective schema.
type CompiledBinding struct {
	ID, Subject, DiagnosticKey string
	Groups                     []string
	Schema                     *jsonschema.Schema
}

// queryResult contains one decoded query result and its exact column names.
type queryResult struct {
	columns []string
	rows    [][]any
}

// queryFunc executes one bounded policy database query.
type queryFunc func(context.Context, string, ...any) (queryResult, error)

// cacheEntry contains one bounded client-existence cache value.
type cacheEntry struct {
	key     string
	value   bool
	expires time.Time
}

// schemaEntry contains one immutable compiled policy schema.
type schemaEntry struct {
	key    string
	schema *jsonschema.Schema
}

// PostgreSQL resolves database policy and owns independent bounded caches.
type PostgreSQL struct {
	cfg       config.PolicyDatabaseConfig
	issuers   map[string]config.TrustIssuerConfig
	query     queryFunc
	close     func()
	logger    *slog.Logger
	mu        sync.Mutex
	clients   map[string]*list.Element
	clientLRU *list.List
	schemas   map[string]*list.Element
	schemaLRU *list.List
	flight    singleflight.Group
	now       func() time.Time
	compile   func([]byte) (*jsonschema.Schema, error)
}

// NewPostgreSQL validates the connection string and creates a dedicated pgx pool.
func NewPostgreSQL(ctx context.Context, connectionString string, cfg config.PolicyDatabaseConfig, issuers map[string]config.TrustIssuerConfig, logger *slog.Logger) (*PostgreSQL, error) {
	poolCfg, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, fmt.Errorf("parse policy database connection")
	}
	if err := requireTLS(poolCfg.ConnConfig); err != nil {
		return nil, err
	}
	poolCfg.MaxConns = cfg.MaxConnections
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	maxBodyLen := backendMessageBodyLimit(cfg)
	poolCfg.ConnConfig.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		frontend := pgproto3.NewFrontend(r, w)
		frontend.SetMaxBodyLen(maxBodyLen)
		return frontend
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create policy database pool")
	}
	if err := validatePool(ctx, pool, cfg); err != nil {
		pool.Close()
		return nil, err
	}
	query := func(ctx context.Context, sql string, args ...any) (queryResult, error) {
		return queryPostgreSQL(ctx, pool, cfg, sql, args...)
	}
	return newPostgreSQL(cfg, issuers, logger, query, pool.Close), nil
}

// queryPostgreSQL streams one known query contract with bounded text-format decoding.
func queryPostgreSQL(ctx context.Context, pool *pgxpool.Pool, cfg config.PolicyDatabaseConfig, sql string, args ...any) (queryResult, error) {
	var columns []string
	var oids [][]uint32
	limit := 1
	switch sql {
	case cfg.Queries.ClientExists:
		columns, oids = []string{"exists"}, [][]uint32{{pgtype.BoolOID}}
	case cfg.Queries.UserAccess:
		columns, oids = []string{"allowed", "groups"}, [][]uint32{{pgtype.BoolOID}, {pgtype.TextArrayOID}}
	case cfg.Queries.TrustBindings:
		columns = []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"}
		oids = [][]uint32{{pgtype.TextOID}, {pgtype.TextOID}, {pgtype.TextOID}, {pgtype.TextOID}, {pgtype.JSONOID, pgtype.JSONBOID}, {pgtype.JSONOID, pgtype.JSONBOID}, {pgtype.JSONOID, pgtype.JSONBOID}, {pgtype.TextArrayOID}}
		limit = cfg.MaxTrustRows
	default:
		return queryResult{}, fmt.Errorf("unknown policy database query")
	}
	formats := pgx.QueryResultFormatsByOID{pgtype.BoolOID: pgx.TextFormatCode, pgtype.TextOID: pgx.TextFormatCode, pgtype.JSONOID: pgx.TextFormatCode, pgtype.JSONBOID: pgx.TextFormatCode, pgtype.TextArrayOID: pgx.TextFormatCode}
	queryArgs := append([]any{formats}, args...)
	rows, err := pool.Query(ctx, sql, queryArgs...)
	if err != nil {
		return queryResult{}, err
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	if err := rows.Err(); err != nil {
		return queryResult{}, err
	}
	if len(fields) != len(columns) {
		// Query can return before an asynchronous receive failure is surfaced.
		// Advance once so a protocol body-limit error is not masked as a column error.
		_ = rows.Next()
		if err := rows.Err(); err != nil {
			return queryResult{}, err
		}
		return queryResult{}, fmt.Errorf("unexpected column count")
	}
	for i, field := range fields {
		accepted := false
		for _, oid := range oids[i] {
			accepted = accepted || field.DataTypeOID == oid
		}
		if field.Name != columns[i] || !accepted || field.Format != pgx.TextFormatCode {
			return queryResult{}, fmt.Errorf("unexpected column contract")
		}
	}
	out := queryResult{columns: columns, rows: make([][]any, 0, limit)}
	messageBytes, jsonBytes := 0, 0
	for rows.Next() {
		raw := rows.RawValues()
		if len(out.rows) >= limit {
			// Retain a sentinel so operation logs report the row that violated cardinality.
			out.rows = append(out.rows, nil)
			return out, fmt.Errorf("policy database result row limit exceeded")
		}
		rowBytes, rowJSONBytes, err := checkRawRow(cfg, columns, raw)
		if err != nil {
			return out, err
		}
		messageBytes += rowBytes
		jsonBytes += rowJSONBytes
		if jsonBytes > cfg.MaxJSONBytes || messageBytes > resultByteLimit(cfg) {
			return out, fmt.Errorf("policy database result exceeds aggregate limit")
		}
		values := make([]any, len(columns))
		scan := make([]any, len(columns))
		for i, accepted := range oids {
			switch accepted[0] {
			case pgtype.BoolOID:
				scan[i] = new(bool)
			case pgtype.TextOID:
				scan[i] = new(string)
			case pgtype.TextArrayOID:
				scan[i] = new([]string)
			default:
				scan[i] = new([]byte)
			}
		}
		if err := rows.Scan(scan...); err != nil {
			return out, err
		}
		for i, destination := range scan {
			switch value := destination.(type) {
			case *bool:
				values[i] = *value
			case *string:
				values[i] = *value
			case *[]string:
				values[i] = *value
			case *[]byte:
				values[i] = append([]byte(nil), (*value)...)
			}
		}
		out.rows = append(out.rows, values)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// checkRawRow rejects nulls and oversized wire values before pgx decoding allocates destinations.
func checkRawRow(cfg config.PolicyDatabaseConfig, columns []string, raw [][]byte) (int, int, error) {
	if len(raw) != len(columns) {
		return 0, 0, fmt.Errorf("unexpected row width")
	}
	groupWire := 2 + cfg.MaxGroups*(2*cfg.MaxGroupBytes+4)
	rowBudget := rawRowBudget(cfg)
	total, jsonTotal := 0, 0
	for i, value := range raw {
		if value == nil {
			return 0, 0, fmt.Errorf("policy database columns must be non-null")
		}
		total += len(value)
		name := columns[i]
		switch name {
		case "client_id", "issuer_id", "subject":
			if len(value) > 256 {
				return 0, 0, fmt.Errorf("identity column exceeds limit")
			}
		case "binding_id":
			if len(value) > 64 {
				return 0, 0, fmt.Errorf("binding identifier exceeds limit")
			}
		case "groups":
			if len(value) > groupWire {
				return 0, 0, fmt.Errorf("groups wire value exceeds limit")
			}
			if err := validateTextArrayWire(value, cfg.MaxGroups, cfg.MaxGroupBytes); err != nil {
				return 0, 0, err
			}
		case "required_claims", "policy_claims", "binding_claims":
			jsonTotal += len(value)
		}
	}
	if jsonTotal > cfg.MaxJSONBytes || total > rowBudget {
		return 0, 0, fmt.Errorf("policy database row exceeds limit")
	}
	return total, jsonTotal, nil
}

// rawRowBudget derives a conservative decoded-message ceiling from configured cell limits.
func rawRowBudget(cfg config.PolicyDatabaseConfig) int {
	groupWire := 2 + cfg.MaxGroups*(2*cfg.MaxGroupBytes+4)
	return 4*256 + groupWire + cfg.MaxJSONBytes + 64
}

// backendMessageBodyLimit bounds a single backend message before pgproto3 allocates its body.
func backendMessageBodyLimit(cfg config.PolicyDatabaseConfig) int {
	// DataRow adds a field count and a four-byte length for each field. The extra
	// allowance also leaves ample room for startup, error, and row metadata.
	return min(maxBackendMessageBody, rawRowBudget(cfg)+8*4+64<<10)
}

// resultByteLimit bounds retained raw result data independently of row count.
func resultByteLimit(cfg config.PolicyDatabaseConfig) int {
	return min(maxBackendMessageBody, cfg.MaxJSONBytes+(2+cfg.MaxGroups*(2*cfg.MaxGroupBytes+4))+4*256+64<<10)
}

// validateTextArrayWire validates a one-dimensional PostgreSQL text[] value without allocating decoded elements.
func validateTextArrayWire(value []byte, maxElements, maxElementBytes int) error {
	if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' {
		return fmt.Errorf("groups must use one-dimensional text array syntax")
	}
	if len(value) == 2 {
		return nil
	}
	i, elements := 1, 0
	for i < len(value)-1 {
		elements++
		if elements > maxElements {
			return fmt.Errorf("group limit exceeded")
		}
		decoded, quoted := 0, false
		if value[i] == '"' {
			quoted = true
			i++
		}
		closed := !quoted
		start := i
		for i < len(value)-1 {
			c := value[i]
			if c == '\\' {
				i++
				if i >= len(value)-1 {
					return fmt.Errorf("malformed groups array escape")
				}
				decoded++
				i++
				continue
			}
			if quoted {
				if c == '"' {
					i++
					closed = true
					break
				}
			} else if c == ',' {
				break
			} else if c == '"' || c == '{' || c == '}' {
				return fmt.Errorf("nested or malformed groups array")
			}
			decoded++
			i++
		}
		if !closed || decoded < 1 || decoded > maxElementBytes {
			return fmt.Errorf("invalid group element")
		}
		if !quoted && strings.EqualFold(string(value[start:i]), "NULL") {
			return fmt.Errorf("null group element")
		}
		if i == len(value)-1 {
			break
		}
		if value[i] != ',' {
			return fmt.Errorf("malformed groups array separator")
		}
		i++
		if i == len(value)-1 {
			return fmt.Errorf("malformed groups array")
		}
	}
	return nil
}

// validatePool eagerly verifies connectivity and configured statements.
func validatePool(ctx context.Context, pool *pgxpool.Pool, cfg config.PolicyDatabaseConfig) error {
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("connect to policy database")
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire policy database validation connection")
	}
	defer connection.Release()
	for _, statement := range []string{cfg.Queries.ClientExists, cfg.Queries.UserAccess, cfg.Queries.TrustBindings} {
		if _, err = connection.Conn().Prepare(ctx, "", statement); err != nil {
			return fmt.Errorf("prepare policy database query")
		}
	}
	return nil
}

// newPostgreSQL constructs a policy database implementation around a narrow query function for deterministic tests.
func newPostgreSQL(cfg config.PolicyDatabaseConfig, issuers map[string]config.TrustIssuerConfig, logger *slog.Logger, query queryFunc, closeFn func()) *PostgreSQL {
	known := make(map[string]config.TrustIssuerConfig, len(issuers))
	for id, issuer := range issuers {
		known[id] = issuer
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PostgreSQL{cfg: cfg, issuers: known, query: query, close: closeFn, logger: logger, clients: map[string]*list.Element{}, clientLRU: list.New(), schemas: map[string]*list.Element{}, schemaLRU: list.New(), now: time.Now, compile: config.CompileCanonicalTrustSchema}
}

// Close closes the dedicated PostgreSQL pool.
func (r *PostgreSQL) Close() {
	if r.close != nil {
		r.close()
	}
}

// ClientExists resolves and caches only definitive positive or negative existence results.
func (r *PostgreSQL) ClientExists(ctx context.Context, clientID string) (bool, error) {
	return r.clientExists(ctx, clientID, true)
}

// clientExists resolves existence, optionally using and populating the cache.
func (r *PostgreSQL) clientExists(ctx context.Context, clientID string, cached bool) (bool, error) {
	start := time.Now()
	cacheState := "miss"
	if !cached {
		cacheState = "bypass"
	}
	var observedRows int
	var finalErr error
	var exists bool
	defer func() {
		r.log("client_exists", outcome(exists, finalErr), clientID, "", time.Since(start), observedRows, cacheState)
	}()
	if !validDynamicClientID(clientID) {
		finalErr = indeterminate(fmt.Errorf("invalid dynamic client identifier"))
		return false, finalErr
	}
	now := r.now()
	r.mu.Lock()
	if e := r.clients[clientID]; cached && e != nil {
		entry := e.Value.(cacheEntry)
		if now.Before(entry.expires) {
			r.clientLRU.MoveToFront(e)
			r.mu.Unlock()
			cacheState = "hit"
			exists = entry.value
			return exists, nil
		}
		r.removeClient(e)
	}
	r.mu.Unlock()
	key := "client:cached:" + clientID
	if !cached {
		key = "client:fresh:" + clientID
	}
	v, err, _ := r.flight.Do(key, func() (any, error) {
		result, queryErr := r.run(ctx, "client_exists", r.cfg.Queries.ClientExists, clientID)
		observedRows = len(result.rows)
		if queryErr != nil {
			return false, queryErr
		}
		if err := exact(result, []string{"exists"}, 1); err != nil {
			return false, indeterminate(err)
		}
		exists, ok := result.rows[0][0].(bool)
		if !ok {
			return false, indeterminate(fmt.Errorf("exists must be non-null boolean"))
		}
		ttl := r.cfg.ClientLookupCache.NegativeTTL.Duration()
		if exists {
			ttl = r.cfg.ClientLookupCache.TTL.Duration()
		}
		if cached {
			r.putClient(clientID, exists, r.now().Add(ttl))
		}
		return exists, nil
	})
	if err != nil {
		finalErr = err
		return false, err
	}
	exists = v.(bool)
	return exists, nil
}

// ResolveUser resolves a normalized subject and returns definitive groups or denial.
func (r *PostgreSQL) ResolveUser(ctx context.Context, clientID, subject string, requireUserGroupsFromPolicy bool) (user ResolvedUser, finalErr error) {
	start := time.Now()
	rows := 0
	defer func() {
		r.log("user_access", outcome(finalErr == nil, finalErr), clientID, "", time.Since(start), rows, "bypass")
	}()
	if !validDynamicClientID(clientID) {
		return ResolvedUser{}, indeterminate(fmt.Errorf("invalid dynamic client identifier"))
	}
	result, err := r.run(ctx, "user_access", r.cfg.Queries.UserAccess, clientID, strings.ToLower(subject))
	rows = len(result.rows)
	if err != nil {
		return ResolvedUser{}, err
	}
	if err := exact(result, []string{"allowed", "groups"}, 1); err != nil {
		return ResolvedUser{}, indeterminate(err)
	}
	allowed, ok := result.rows[0][0].(bool)
	if !ok {
		return ResolvedUser{}, indeterminate(fmt.Errorf("allowed must be non-null boolean"))
	}
	groups, err := r.groups(result.rows[0][1])
	if err != nil {
		return ResolvedUser{}, err
	}
	if !allowed || (requireUserGroupsFromPolicy && len(groups) == 0) {
		return ResolvedUser{}, ErrDenied
	}
	return ResolvedUser{Groups: groups}, nil
}

// CompileBindings validates current dynamic rows and compiles or reuses immutable schemas.
func (r *PostgreSQL) CompileBindings(clientID, issuerID string, rows []DynamicTrustRow) ([]CompiledBinding, error) {
	issuer, ok := r.issuers[issuerID]
	if !ok {
		return nil, indeterminate(fmt.Errorf("issuer is not configured in service_token_issuers"))
	}
	if len(rows) > r.cfg.MaxTrustRows {
		return nil, indeterminate(fmt.Errorf("trust row limit exceeded"))
	}
	seen := map[string]bool{}
	out := make([]CompiledBinding, 0, len(rows))
	totalJSONBytes := 0
	for _, row := range rows {
		if row.ClientID != clientID || row.IssuerID != issuerID || !config.ValidTrustBindingID(row.BindingID) || seen[row.BindingID] {
			return nil, indeterminate(fmt.Errorf("invalid trust row identity"))
		}
		seen[row.BindingID] = true
		if !strings.HasPrefix(row.Subject, "trusted:") || len(row.Subject) > 256 {
			return nil, indeterminate(fmt.Errorf("invalid trust subject"))
		}
		groups, err := r.groups(row.Groups)
		if err != nil || len(groups) == 0 {
			if err == nil {
				err = indeterminate(fmt.Errorf("trust groups empty"))
			}
			return nil, err
		}
		totalJSONBytes += jsonBytes(row.RequiredClaims) + jsonBytes(row.PolicyClaims) + jsonBytes(row.BindingClaims)
		if totalJSONBytes > r.cfg.MaxJSONBytes {
			return nil, indeterminate(fmt.Errorf("trust JSON limit exceeded"))
		}
		claims := cloneClaims(row.PolicyClaims)
		for k, v := range row.BindingClaims {
			claims[k] = v
		}
		for name := range claims {
			if err := config.ValidateTrustClaimName(name, issuer.Provider); err != nil {
				return nil, indeterminate(err)
			}
		}
		for name := range row.RequiredClaims {
			if err := config.ValidateTrustClaimName(name, issuer.Provider); err != nil {
				return nil, indeterminate(err)
			}
		}
		canonical, err := config.BuildTrustSchema(claims, row.RequiredClaims)
		if err != nil {
			return nil, indeterminate(fmt.Errorf("build dynamic trust schema: %w", err))
		}
		digest := sha256.Sum256(canonical)
		key := clientID + "/" + issuerID + "/" + row.BindingID + "/" + hex.EncodeToString(digest[:])
		schema, err := r.compiledSchema(key, canonical)
		if err != nil {
			return nil, indeterminate(fmt.Errorf("compile dynamic trust schema: %w", err))
		}
		out = append(out, CompiledBinding{ID: row.BindingID, Subject: row.Subject, Groups: groups, Schema: schema, DiagnosticKey: key})
	}
	return out, nil
}

// ResolveTrust queries strict rows and returns compiled current bindings.
func (r *PostgreSQL) ResolveTrust(ctx context.Context, clientID, issuerID string) (bindings []CompiledBinding, finalErr error) {
	start := time.Now()
	rowsObserved := 0
	defer func() {
		r.log("trust_bindings", outcome(finalErr == nil, finalErr), clientID, issuerID, time.Since(start), rowsObserved, "bypass")
	}()
	if !validDynamicClientID(clientID) {
		return nil, indeterminate(fmt.Errorf("invalid dynamic client identifier"))
	}
	result, err := r.run(ctx, "trust_bindings", r.cfg.Queries.TrustBindings, clientID, issuerID)
	rowsObserved = len(result.rows)
	if err != nil {
		return nil, err
	}
	want := []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"}
	if err := exact(result, want, -1); err != nil {
		return nil, indeterminate(err)
	}
	if len(result.rows) > r.cfg.MaxTrustRows {
		return nil, indeterminate(fmt.Errorf("trust row limit exceeded"))
	}
	rows := make([]DynamicTrustRow, 0, len(result.rows))
	for _, values := range result.rows {
		row, decodeErr := decodeTrustRow(values)
		if decodeErr != nil {
			return nil, indeterminate(decodeErr)
		}
		rows = append(rows, row)
	}
	return r.CompileBindings(clientID, issuerID, rows)
}

// run executes one policy database query within the configured timeout.
func (r *PostgreSQL) run(ctx context.Context, name, sql string, args ...any) (queryResult, error) {
	deadline, cancel := context.WithTimeout(ctx, r.cfg.QueryTimeout.Duration())
	defer cancel()
	result, err := r.query(deadline, sql, args...)
	if err != nil {
		return result, indeterminate(fmt.Errorf("policy database query %s: %w", name, err))
	}
	return result, nil
}

// log records one sanitized policy database query outcome.
func (r *PostgreSQL) log(query, outcome, client, issuer string, duration time.Duration, rows int, cache string) {
	r.logger.Info("policy database query", "query", query, "outcome", outcome, "client_id", client, "issuer_id", issuer, "duration", duration, "rows", rows, "cache", cache)
}

// outcome classifies a resolver operation without exposing its error.
func outcome(allowed bool, err error) string {
	if err == nil && allowed {
		return "allowed"
	}
	if errors.Is(err, ErrDenied) || err == nil {
		return "denied"
	}
	return "indeterminate"
}

// exact validates a query result's column order, row count, and row widths.
func exact(result queryResult, columns []string, rows int) error {
	if len(result.columns) != len(columns) {
		return fmt.Errorf("unexpected column count")
	}
	for i := range columns {
		if result.columns[i] != columns[i] {
			return fmt.Errorf("unexpected column contract")
		}
	}
	if rows >= 0 && len(result.rows) != rows {
		return fmt.Errorf("unexpected row count")
	}
	for _, row := range result.rows {
		if len(row) != len(columns) {
			return fmt.Errorf("unexpected row width")
		}
	}
	return nil
}

// indeterminate wraps an error as a retryable auth resolution failure.
func indeterminate(err error) error { return &IndeterminateError{Err: err} }

// requireTLS rejects any remote PostgreSQL connection attempt that permits plaintext.
func requireTLS(cfg *pgx.ConnConfig) error {
	if !isLocalPostgreSQLHost(cfg.Host) && cfg.TLSConfig == nil {
		return fmt.Errorf("policy database requires TLS for remote connections")
	}
	for _, fallback := range cfg.Fallbacks {
		if !isLocalPostgreSQLHost(fallback.Host) && fallback.TLSConfig == nil {
			return fmt.Errorf("policy database requires TLS for remote connections")
		}
	}
	return nil
}

// isLocalPostgreSQLHost reports whether a host is safe for plaintext development.
func isLocalPostgreSQLHost(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// groups validates, deduplicates, and sorts a PostgreSQL group array.
func (r *PostgreSQL) groups(value any) ([]string, error) {
	groups, err := decodeTextArray(value)
	if err != nil {
		return nil, indeterminate(fmt.Errorf("groups must be non-null text array"))
	}
	if len(groups) > r.cfg.MaxGroups {
		return nil, indeterminate(fmt.Errorf("group limit exceeded"))
	}
	unique := map[string]struct{}{}
	for _, group := range groups {
		if group == "" || len(group) > r.cfg.MaxGroupBytes {
			return nil, indeterminate(fmt.Errorf("invalid group"))
		}
		unique[group] = struct{}{}
	}
	out := make([]string, 0, len(unique))
	for group := range unique {
		out = append(out, group)
	}
	sort.Strings(out)
	return out, nil
}

// putClient inserts one bounded client-existence cache value.
func (r *PostgreSQL) putClient(key string, value bool, expires time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.clients[key]; old != nil {
		r.removeClient(old)
	}
	e := r.clientLRU.PushFront(cacheEntry{key: key, value: value, expires: expires})
	r.clients[key] = e
	for r.clientLRU.Len() > r.cfg.ClientLookupCache.MaxEntries {
		r.removeClient(r.clientLRU.Back())
	}
}

// removeClient removes one client-existence cache entry.
func (r *PostgreSQL) removeClient(e *list.Element) {
	delete(r.clients, e.Value.(cacheEntry).key)
	r.clientLRU.Remove(e)
}

// compiledSchema returns a cached schema or coalesces compilation and insertion on a miss.
func (r *PostgreSQL) compiledSchema(key string, canonical []byte) (*jsonschema.Schema, error) {
	r.mu.Lock()
	if e := r.schemas[key]; e != nil {
		r.schemaLRU.MoveToFront(e)
		schema := e.Value.(schemaEntry).schema
		r.mu.Unlock()
		return schema, nil
	}
	r.mu.Unlock()
	value, err, _ := r.flight.Do("schema:"+key, func() (any, error) {
		r.mu.Lock()
		if e := r.schemas[key]; e != nil {
			schema := e.Value.(schemaEntry).schema
			r.schemaLRU.MoveToFront(e)
			r.mu.Unlock()
			return schema, nil
		}
		r.mu.Unlock()
		compiled, compileErr := r.compile(canonical)
		if compileErr != nil {
			return nil, compileErr
		}
		r.mu.Lock()
		e := r.schemaLRU.PushFront(schemaEntry{key: key, schema: compiled})
		r.schemas[key] = e
		for r.schemaLRU.Len() > r.cfg.PolicyBuildCache.MaxEntries {
			old := r.schemaLRU.Back()
			delete(r.schemas, old.Value.(schemaEntry).key)
			r.schemaLRU.Remove(old)
		}
		r.mu.Unlock()
		return compiled, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*jsonschema.Schema), nil
}

// validDynamicClientID enforces the bounded policy database and cache-key contracts.
func validDynamicClientID(id string) bool {
	return id != "" && len(id) <= 256 && !strings.ContainsRune(id, '\x00')
}

// cloneClaims returns a shallow copy of immutable raw claim fragments.
func cloneClaims(source map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(source))
	for k, v := range source {
		out[k] = v
	}
	return out
}

// jsonBytes returns the aggregate encoded size of claim names and values.
func jsonBytes(source map[string]json.RawMessage) int {
	total := 0
	for k, v := range source {
		total += len(k) + len(v)
	}
	return total
}

// decodeTrustRow decodes one strict trust binding query row.
func decodeTrustRow(v []any) (DynamicTrustRow, error) {
	if len(v) != 8 {
		return DynamicTrustRow{}, fmt.Errorf("invalid trust row width")
	}
	strings4 := make([]string, 4)
	for i := range strings4 {
		var ok bool
		strings4[i], ok = v[i].(string)
		if !ok {
			return DynamicTrustRow{}, fmt.Errorf("trust identity columns must be non-null text")
		}
	}
	maps := make([]map[string]json.RawMessage, 3)
	for i := range maps {
		var raw []byte
		switch typed := v[i+4].(type) {
		case []byte:
			raw = typed
		case string:
			raw = []byte(typed)
		default:
			return DynamicTrustRow{}, fmt.Errorf("trust claim columns must be JSON objects")
		}
		if err := json.Unmarshal(raw, &maps[i]); err != nil || maps[i] == nil {
			return DynamicTrustRow{}, fmt.Errorf("trust claim columns must be JSON objects")
		}
	}
	groups, err := decodeTextArray(v[7])
	if err != nil {
		return DynamicTrustRow{}, fmt.Errorf("trust groups must be non-null text array")
	}
	return DynamicTrustRow{ClientID: strings4[0], IssuerID: strings4[1], BindingID: strings4[2], Subject: strings4[3], RequiredClaims: maps[0], PolicyClaims: maps[1], BindingClaims: maps[2], Groups: groups}, nil
}

// decodeTextArray accepts pgx text[] representations and rejects null elements.
func decodeTextArray(value any) ([]string, error) {
	switch typed := value.(type) {
	case []string:
		return typed, nil
	case []any:
		out := make([]string, len(typed))
		for i, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("null or non-text array element")
			}
			out[i] = text
		}
		return out, nil
	default:
		return nil, fmt.Errorf("not a text array")
	}
}
