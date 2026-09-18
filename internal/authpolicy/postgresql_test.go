// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/truster-dev/truster/v2/internal/config"
)

// TestPostgreSQLOperationLogs verifies final outcomes, cache state, malformed results, and subject redaction.
func TestPostgreSQLOperationLogs(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	cfg := testConfig()
	r := newPostgreSQL(cfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, logger, func(_ context.Context, sql string, _ ...any) (queryResult, error) {
		switch sql {
		case "exists":
			return queryResult{columns: []string{"exists"}, rows: [][]any{{false}}}, nil
		case "user":
			return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{false, []string{}}}}, nil
		default:
			return queryResult{columns: []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"}, rows: [][]any{{"wrong-client", "issuer", "binding", "trusted:secret-subject", []byte(`{}`), []byte(`{}`), []byte(`{}`), []string{"group"}}}}, nil
		}
	}, nil)
	if exists, err := r.ClientExists(context.Background(), "client"); err != nil || exists {
		t.Fatalf("exists=%v error=%v", exists, err)
	}
	_, _ = r.ClientExists(context.Background(), "client")
	if _, err := r.ResolveUser(context.Background(), "client", "secret-user@example.com", false); !errors.Is(err, ErrDenied) {
		t.Fatalf("user error=%v", err)
	}
	if _, err := r.ResolveTrust(context.Background(), "client", "issuer"); !IsIndeterminate(err) {
		t.Fatalf("trust error=%v", err)
	}
	r.query = func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"wrong"}, rows: [][]any{{true}}}, nil
	}
	if _, err := r.clientExists(context.Background(), "malformed", false); !IsIndeterminate(err) {
		t.Fatalf("malformed error=%v", err)
	}

	logs := output.String()
	for _, fragment := range []string{`"msg":"policy database query"`, `"query":"client_exists"`, `"outcome":"denied"`, `"cache":"miss"`, `"cache":"hit"`, `"query":"user_access"`, `"query":"trust_bindings"`, `"outcome":"indeterminate"`, `"cache":"bypass"`, `"rows":1`, `"client_id":"client"`, `"issuer_id":"issuer"`} {
		if !strings.Contains(logs, fragment) {
			t.Errorf("logs missing %s: %s", fragment, logs)
		}
	}
	for _, secret := range []string{"secret-user@example.com", "trusted:secret-subject"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs leaked subject %q: %s", secret, logs)
		}
	}
}

// testConfig returns bounded policy database settings for unit tests.
func testConfig() config.PolicyDatabaseConfig {
	return config.PolicyDatabaseConfig{
		Queries:           config.PolicyQueries{ClientExists: "exists", UserAccess: "user", TrustBindings: "trust"},
		ClientLookupCache: config.ClientLookupCacheConfig{TTL: config.Duration(time.Minute), NegativeTTL: config.Duration(time.Minute), MaxEntries: 2},
		PolicyBuildCache:  config.PolicyBuildCacheConfig{MaxEntries: 2}, QueryTimeout: config.Duration(time.Second),
		MaxTrustRows: 2, MaxGroups: 3, MaxGroupBytes: 20, MaxJSONBytes: 4096,
	}
}

// TestClientLookupCacheCoalescesAndClassifies verifies bounded lookup reuse and malformed result classification.
func TestClientLookupCacheCoalescesAndClassifies(t *testing.T) {
	var calls atomic.Int32
	query := func(_ context.Context, _ string, _ ...any) (queryResult, error) {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		return queryResult{columns: []string{"exists"}, rows: [][]any{{true}}}, nil
	}
	r := newPostgreSQL(testConfig(), nil, nil, query, nil)
	done := make(chan error, 8)
	for range 8 {
		go func() { _, err := r.ClientExists(context.Background(), "client"); done <- err }()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("query calls = %d, want 1", calls.Load())
	}
	r = newPostgreSQL(testConfig(), nil, nil, func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"wrong"}, rows: [][]any{{true}}}, nil
	}, nil)
	if _, err := r.ClientExists(context.Background(), "bad"); !IsIndeterminate(err) {
		t.Fatalf("error = %v, want indeterminate", err)
	}
}

// TestUserGroupsNormalizationAndDenial verifies strict groups and definitive policy outcomes.
func TestUserGroupsNormalizationAndDenial(t *testing.T) {
	r := newPostgreSQL(testConfig(), nil, nil, func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{true, []string{"z", "a", "z"}}}}, nil
	}, nil)
	result, err := r.ResolveUser(context.Background(), "client", "USER@EXAMPLE.COM", true)
	if err != nil || len(result.Groups) != 2 || result.Groups[0] != "a" {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	r.query = func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{false, []string{}}}}, nil
	}
	if _, err := r.ResolveUser(context.Background(), "client", "user@example.com", false); !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want denial", err)
	}
	r.query = func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{true, []string{}}}}, nil
	}
	if _, err := r.ResolveUser(context.Background(), "client", "user@example.com", true); !errors.Is(err, ErrDenied) {
		t.Fatalf("required empty groups error = %v, want denial", err)
	}
	if user, err := r.ResolveUser(context.Background(), "client", "user@example.com", false); err != nil || len(user.Groups) != 0 {
		t.Fatalf("optional empty groups user = %#v, error = %v", user, err)
	}
}

// TestPolicyQueriesFollowReplicaSnapshots verifies user and trust rows are not retained after a replica catches up.
func TestPolicyQueriesFollowReplicaSnapshots(t *testing.T) {
	var userQueries, trustQueries int
	r := newPostgreSQL(testConfig(), map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil, func(_ context.Context, sql string, _ ...any) (queryResult, error) {
		switch sql {
		case "user":
			userQueries++
			groups := []string{"old-group"}
			if userQueries > 1 {
				groups = []string{"current-group"}
			}
			return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{true, groups}}}, nil
		case "trust":
			trustQueries++
			subject, groups := "trusted:old-subject", []string{"old-group"}
			if trustQueries > 1 {
				subject, groups = "trusted:current-subject", []string{"current-group"}
			}
			return queryResult{
				columns: []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"},
				rows:    [][]any{{"client", "issuer", "binding", subject, []byte(`{}`), []byte(`{}`), []byte(`{}`), groups}},
			}, nil
		default:
			return queryResult{}, errors.New("unexpected query")
		}
	}, nil)

	oldUser, err := r.ResolveUser(context.Background(), "client", "user@example.com", true)
	if err != nil || !slices.Equal(oldUser.Groups, []string{"old-group"}) {
		t.Fatalf("lagging user snapshot = %#v, error = %v", oldUser, err)
	}
	currentUser, err := r.ResolveUser(context.Background(), "client", "user@example.com", true)
	if err != nil || !slices.Equal(currentUser.Groups, []string{"current-group"}) {
		t.Fatalf("current user snapshot = %#v, error = %v", currentUser, err)
	}
	oldTrust, err := r.ResolveTrust(context.Background(), "client", "issuer")
	if err != nil || len(oldTrust) != 1 || oldTrust[0].Subject != "trusted:old-subject" || !slices.Equal(oldTrust[0].Groups, []string{"old-group"}) {
		t.Fatalf("lagging trust snapshot = %#v, error = %v", oldTrust, err)
	}
	currentTrust, err := r.ResolveTrust(context.Background(), "client", "issuer")
	if err != nil || len(currentTrust) != 1 || currentTrust[0].Subject != "trusted:current-subject" || !slices.Equal(currentTrust[0].Groups, []string{"current-group"}) {
		t.Fatalf("current trust snapshot = %#v, error = %v", currentTrust, err)
	}
	if oldTrust[0].Schema != currentTrust[0].Schema {
		t.Fatal("immutable policy schema was not reused across replica snapshots")
	}
}

// TestDynamicBindingInheritanceAndPolicyBuildCache verifies override composition, matching, and immutable build reuse.
func TestDynamicBindingInheritanceAndPolicyBuildCache(t *testing.T) {
	r := newPostgreSQL(testConfig(), map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil, nil, nil)
	row := DynamicTrustRow{ClientID: "client", IssuerID: "issuer", BindingID: "binding", Subject: "trusted:user", Groups: []string{"b", "a"},
		RequiredClaims: map[string]json.RawMessage{"shared": json.RawMessage(`{"type":"integer"}`)},
		PolicyClaims:   map[string]json.RawMessage{"shared": json.RawMessage(`{"const":1}`)},
		BindingClaims:  map[string]json.RawMessage{"shared": json.RawMessage(`{"const":2}`)}}
	first, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Schema != second[0].Schema {
		t.Fatal("unchanged effective schema was not reused")
	}
	if err := first[0].Schema.Validate(map[string]any{"shared": 2}); err != nil {
		t.Fatalf("matching schema rejected: %v", err)
	}
	if err := first[0].Schema.Validate(map[string]any{"shared": "2"}); err == nil {
		t.Fatal("non-matching schema accepted")
	}
	row.ClientID = "other"
	if _, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row}); !IsIndeterminate(err) {
		t.Fatalf("error = %v, want indeterminate", err)
	}
	row.ClientID = "client"
	row.RequiredClaims = map[string]json.RawMessage{"subject": json.RawMessage(`{"$ref":"https://example.com/schema"}`)}
	if _, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row}); !IsIndeterminate(err) {
		t.Fatalf("invalid dynamic schema error = %v, want indeterminate", err)
	}
}

// TestTLSRequirement verifies every remote connection attempt requires TLS.
func TestTLSRequirement(t *testing.T) {
	tests := []struct {
		name             string
		connectionString string
		wantError        bool
	}{
		{"remote plaintext", "postgres://user:pass@db.example.com/database?sslmode=disable", true},
		{"remote plaintext fallback", "postgres://user:pass@db.example.com/database?sslmode=prefer", true},
		{"remote TLS", "postgres://user:pass@db.example.com/database?sslmode=require", false},
		{"loopback plaintext", "postgres://user:pass@127.0.0.1/database?sslmode=disable", false},
		{"remote fallback behind loopback", "postgres://user:pass@localhost,db.example.com/database?sslmode=disable", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := pgx.ParseConfig(test.connectionString)
			if err != nil {
				t.Fatal(err)
			}
			err = requireTLS(cfg)
			if (err != nil) != test.wantError {
				t.Fatalf("requireTLS() error = %v, want error = %v", err, test.wantError)
			}
		})
	}
}

// TestPGXValueDecoding verifies JSON text and generic text arrays while rejecting nulls.
func TestPGXValueDecoding(t *testing.T) {
	row, err := decodeTrustRow([]any{"client", "issuer", "binding", "trusted:user", "{}", []byte(`{}`), []byte(`{"sub":{"const":9007199254740993}}`), []any{"b", "a"}})
	if err != nil || len(row.Groups) != 2 {
		t.Fatalf("row = %#v, error = %v", row, err)
	}
	if string(row.BindingClaims["sub"]) != `{"const":9007199254740993}` {
		t.Fatalf("decoded binding claims = %s", row.BindingClaims["sub"])
	}
	if _, err = decodeTextArray([]any{"group", nil}); err == nil {
		t.Fatal("null text[] element accepted")
	}
}

// TestValidateTextArrayWire verifies bounded parsing before pgx allocates decoded groups.
func TestValidateTextArrayWire(t *testing.T) {
	tests := []struct {
		name  string
		value string
		ok    bool
	}{
		{"empty", `{}`, true},
		{"quoted comma and braces", `{"a,b","{x}"}`, true},
		{"escaped quote and slash", `{"a\\\"b","c\\\\d"}`, true},
		{"escaped comma unquoted", `{a\\,b}`, true},
		{"null", `{NULL}`, false},
		{"quoted null", `{"NULL"}`, true},
		{"empty element", `{a,,b}`, false},
		{"empty quoted", `{""}`, false},
		{"excess", `{a,b,c,d}`, false},
		{"oversized decoded", `{"123456"}`, false},
		{"nested", `{{a}}`, false},
		{"dimension prefix", `[1:1]={a}`, false},
		{"unterminated quote", `{"abc}`, false},
		{"trailing escape", `{abc\}`, false},
		{"text after quote", `{"a"b}`, false},
		{"trailing comma", `{a,}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTextArrayWire([]byte(tt.value), 3, 5)
			if (err == nil) != tt.ok {
				t.Fatalf("validateTextArrayWire(%q) error=%v, want valid=%v", tt.value, err, tt.ok)
			}
		})
	}
}

// TestCompileBindingsAggregateJSONLimit verifies the JSON limit applies to the entire result.
func TestCompileBindingsAggregateJSONLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxJSONBytes = 20
	r := newPostgreSQL(cfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil, nil, nil)
	row := DynamicTrustRow{ClientID: "client", IssuerID: "issuer", Subject: "trusted:user", Groups: []string{"group"}, RequiredClaims: map[string]json.RawMessage{}, PolicyClaims: map[string]json.RawMessage{"x": json.RawMessage(`{"const":1}`)}, BindingClaims: map[string]json.RawMessage{}}
	row.BindingID = "one"
	other := row
	other.BindingID = "two"
	if _, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row, other}); !IsIndeterminate(err) {
		t.Fatalf("aggregate JSON error=%v", err)
	}
}

// TestDynamicIdentifierBounds verifies invalid dynamic identifiers never reach a query or cache.
func TestDynamicIdentifierBounds(t *testing.T) {
	var calls atomic.Int32
	r := newPostgreSQL(testConfig(), map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil, func(context.Context, string, ...any) (queryResult, error) {
		calls.Add(1)
		return queryResult{}, nil
	}, nil)
	for _, id := range []string{"", "bad\x00id", strings.Repeat("x", 257)} {
		if _, err := r.ClientExists(context.Background(), id); !IsIndeterminate(err) {
			t.Fatalf("client %q error = %v", id, err)
		}
	}
	if calls.Load() != 0 || len(r.clients) != 0 {
		t.Fatalf("calls=%d cache=%d", calls.Load(), len(r.clients))
	}
	base := DynamicTrustRow{ClientID: "client", IssuerID: "issuer", Subject: "trusted:user", Groups: []string{"group"}, RequiredClaims: map[string]json.RawMessage{}, PolicyClaims: map[string]json.RawMessage{}, BindingClaims: map[string]json.RawMessage{}}
	for _, id := range []string{"bad id", strings.Repeat("x", 65)} {
		base.BindingID = id
		if _, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{base}); !IsIndeterminate(err) {
			t.Fatalf("binding %q error = %v", id, err)
		}
	}
}

// TestClientLookupCachePolicy verifies positive and negative TTLs, expiry, eviction, false values, and no stale fallback.
func TestClientLookupCachePolicy(t *testing.T) {
	cfg := testConfig()
	cfg.ClientLookupCache.TTL, cfg.ClientLookupCache.NegativeTTL = config.Duration(time.Hour), config.Duration(time.Minute)
	now := time.Unix(100, 0)
	var calls atomic.Int32
	fail := false
	r := newPostgreSQL(cfg, nil, nil, func(_ context.Context, _ string, args ...any) (queryResult, error) {
		calls.Add(1)
		if fail {
			return queryResult{}, errors.New("database unavailable")
		}
		return queryResult{columns: []string{"exists"}, rows: [][]any{{args[0] != "missing"}}}, nil
	}, nil)
	r.now = func() time.Time { return now }
	if exists, err := r.ClientExists(context.Background(), "missing"); err != nil || exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}
	_, _ = r.ClientExists(context.Background(), "missing")
	if calls.Load() != 1 {
		t.Fatalf("negative cache calls=%d", calls.Load())
	}
	now = now.Add(2 * time.Minute)
	_, _ = r.ClientExists(context.Background(), "missing")
	if calls.Load() != 2 {
		t.Fatalf("negative expiry calls=%d", calls.Load())
	}
	_, _ = r.ClientExists(context.Background(), "one")
	_, _ = r.ClientExists(context.Background(), "two")
	_, _ = r.ClientExists(context.Background(), "missing")
	if calls.Load() != 5 {
		t.Fatalf("eviction calls=%d", calls.Load())
	}
	fail = true
	if exists, err := r.ClientExists(context.Background(), "two"); err != nil || !exists || calls.Load() != 5 {
		t.Fatalf("unexpired cached result exists=%v error=%v calls=%d", exists, err, calls.Load())
	}
	now = now.Add(2 * time.Hour)
	if _, err := r.ClientExists(context.Background(), "one"); !IsIndeterminate(err) {
		t.Fatalf("stale fallback error=%v", err)
	}
}

// TestPolicyBuildCache verifies hits, concurrent miss coalescing, digest changes, and bounded eviction.
func TestPolicyBuildCache(t *testing.T) {
	cfg := testConfig()
	cfg.PolicyBuildCache.MaxEntries = 1
	r := newPostgreSQL(cfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil, nil, nil)
	original := r.compile
	var compilations atomic.Int32
	r.compile = func(raw []byte) (*jsonschema.Schema, error) { compilations.Add(1); return original(raw) }
	row := DynamicTrustRow{ClientID: "client", IssuerID: "issuer", BindingID: "binding", Subject: "trusted:user", Groups: []string{"group"}, RequiredClaims: map[string]json.RawMessage{}, PolicyClaims: map[string]json.RawMessage{}, BindingClaims: map[string]json.RawMessage{"n": json.RawMessage(`{"const":1}`)}}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if compilations.Load() != 1 {
		t.Fatalf("unchanged compilations=%d", compilations.Load())
	}
	row.BindingClaims["n"] = json.RawMessage(`{"const":2}`)
	if _, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row}); err != nil {
		t.Fatal(err)
	}
	if compilations.Load() != 2 {
		t.Fatalf("changed compilations=%d", compilations.Load())
	}
	row.BindingClaims["n"] = json.RawMessage(`{"const":1}`)
	if _, err := r.CompileBindings("client", "issuer", []DynamicTrustRow{row}); err != nil {
		t.Fatal(err)
	}
	if compilations.Load() != 3 {
		t.Fatalf("evicted compilations=%d", compilations.Load())
	}
}
