// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/truster-dev/truster/v3/internal/config"
)

// BenchmarkCachedClientLookup measures the default hot client-existence path.
func BenchmarkCachedClientLookup(b *testing.B) {
	r := newPostgreSQL(testConfig(), nil, benchmarkLogger(), func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"exists"}, rows: [][]any{{true}}}, nil
	}, nil)
	_, _ = r.ClientExists(context.Background(), "cluster")
	b.ResetTimer()
	for range b.N {
		if _, err := r.ClientExists(context.Background(), "cluster"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUserAccessNormalization measures bounded group normalization without a database.
func BenchmarkUserAccessNormalization(b *testing.B) {
	r := newPostgreSQL(testConfig(), nil, benchmarkLogger(), func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{true, []string{"operators", "viewers", "operators"}}}}, nil
	}, nil)
	b.ResetTimer()
	for range b.N {
		if _, err := r.ResolveUser(context.Background(), "cluster", "USER@example.com", true); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTrustRowQueryCompile measures decoding and compiling a representative trust query result.
func BenchmarkTrustRowQueryCompile(b *testing.B) {
	cfg := testConfig()
	r := newPostgreSQL(cfg, map[string]config.TrustIssuerConfig{"github": {Provider: "github"}}, benchmarkLogger(), func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"}, rows: [][]any{{"cluster", "github", "deploy", "trusted:deploy", []byte(`{}`), []byte(`{"repository":{"const":"acme/app"}}`), []byte(`{}`), []string{"deployers"}}}}, nil
	}, nil)
	b.ResetTimer()
	for range b.N {
		if _, err := r.ResolveTrustBindings(context.Background(), "cluster", "github", r.issuers["github"]); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDefaultGroupLimit measures normalization at the default group-count ceiling.
func BenchmarkDefaultGroupLimit(b *testing.B) {
	cfg := testConfig()
	cfg.MaxGroups = 100
	groups := make([]string, cfg.MaxGroups)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%03d", cfg.MaxGroups-i)
	}
	r := newPostgreSQL(cfg, nil, benchmarkLogger(), func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{true, groups}}}, nil
	}, nil)
	b.ResetTimer()
	for range b.N {
		if _, err := r.ResolveUser(context.Background(), "cluster", "user@example.com", true); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDefaultTrustRowLimit measures schema reuse at the default trust-row ceiling.
func BenchmarkDefaultTrustRowLimit(b *testing.B) {
	cfg := testConfig()
	cfg.MaxTrustRows = 100
	cfg.MaxGroups = 100
	cfg.MaxJSONBytes = 64 << 10
	cfg.PolicyBuildCache.MaxEntries = 10000
	rows := make([][]any, cfg.MaxTrustRows)
	for i := range rows {
		rows[i] = []any{"cluster", "github", fmt.Sprintf("binding-%03d", i), "trusted:deploy", []byte(`{}`), []byte(`{"repository":{"const":"acme/app"}}`), []byte(`{}`), []string{"deployers"}}
	}
	r := newPostgreSQL(cfg, map[string]config.TrustIssuerConfig{"github": {Provider: "github"}}, benchmarkLogger(), func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"}, rows: rows}, nil
	}, nil)
	if _, err := r.ResolveTrustBindings(context.Background(), "cluster", "github", r.issuers["github"]); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if _, err := r.ResolveTrustBindings(context.Background(), "cluster", "github", r.issuers["github"]); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnchangedSchemaReuse measures immutable policy-build cache reuse.
func BenchmarkUnchangedSchemaReuse(b *testing.B) { benchmarkSchemaCompilation(b, false) }

// BenchmarkChangedSchemaCompilation measures compilation when effective policy changes.
func BenchmarkChangedSchemaCompilation(b *testing.B) { benchmarkSchemaCompilation(b, true) }

// benchmarkSchemaCompilation measures one bounded dynamic binding compilation mode.
func benchmarkSchemaCompilation(b *testing.B, changed bool) {
	cfg := testConfig()
	cfg.PolicyBuildCache.MaxEntries = 10000
	r := newPostgreSQL(cfg, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil, nil, nil)
	row := DynamicTrustRow{ClientID: "cluster", IssuerID: "issuer", BindingID: "binding", Subject: "trusted:user", Groups: []string{"viewers"}, RequiredClaims: map[string]json.RawMessage{}, PolicyClaims: map[string]json.RawMessage{}, BindingClaims: map[string]json.RawMessage{"tenant": json.RawMessage(`{"const":"0"}`)}}
	b.ResetTimer()
	for i := range b.N {
		if changed {
			row.BindingClaims["tenant"] = json.RawMessage(fmt.Sprintf(`{"const":"%d"}`, i))
		}
		if _, err := r.compileBindings("cluster", "issuer", r.issuers["issuer"], []DynamicTrustRow{row}); err != nil {
			b.Fatal(err)
		}
	}
}

// benchmarkLogger discards structured operation logs that are not under test.
func benchmarkLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
