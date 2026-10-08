// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truster-dev/truster/v2/internal/config"
)

// TestResolverStaticPrecedenceAndPolicyDatabaseDefaults verifies deterministic client ownership and effective policy.
func TestResolverStaticPrecedenceAndPolicyDatabaseDefaults(t *testing.T) {
	var calls atomic.Int32
	policyDatabaseConfig := testConfig()
	policyDatabaseConfig.RedirectURIs = []string{"https://dynamic.example/callback"}
	requireUserGroupsFromPolicy := false
	policyDatabaseConfig.ClientDefaults = config.PolicyClientDefaults{RequireUserGroupsFromPolicy: &requireUserGroupsFromPolicy, RefreshTokens: config.RefreshTokenConfig{Enabled: true, AllowOfflineAccess: true}}
	cfg := &config.Config{
		ServiceTokenIssuers: map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc", IssuerURL: "https://issuer.example", SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}},
		StaticPolicy: config.StaticPolicyConfig{
			Clients: map[string]config.ClientConfig{"static": {
				UserGroupMapping: "static-groups",
				TrustBindings:    []config.TrustBindingConfig{{Effective: &config.EffectiveTrustBinding{ID: "static-binding", Issuer: "issuer"}}},
			}},
			DefaultRedirectURIs: []string{"https://static.example/callback"},
			UserGroupMappings:   map[string]map[string][]string{"static-groups": {"user@example.com": {"viewers", "admins", "viewers"}}},
		},
		PolicyDatabase: &policyDatabaseConfig,
	}
	policyDatabase := newPostgreSQL(policyDatabaseConfig, nil, nil, func(_ context.Context, query string, _ ...any) (queryResult, error) {
		calls.Add(1)
		switch query {
		case "exists":
			return queryResult{columns: []string{"exists"}, rows: [][]any{{true}}}, nil
		case "user":
			return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{true, []string{"database-group"}}}}, nil
		default:
			t.Fatalf("unexpected query %q", query)
			return queryResult{}, nil
		}
	}, nil)
	resolver := NewResolver(cfg, policyDatabase)
	static, err := resolver.ResolveClient(context.Background(), "static", true)
	if err != nil || static.source != clientSourceStatic || calls.Load() != 0 || static.Config.RedirectURIs[0] != "https://static.example/callback" {
		t.Fatalf("static = %#v, calls = %d, error = %v", static, calls.Load(), err)
	}
	staticUser, err := resolver.ResolveUser(context.Background(), static, " USER@EXAMPLE.COM ")
	if err != nil || calls.Load() != 0 || len(staticUser.Groups) != 2 || staticUser.Groups[0] != "admins" {
		t.Fatalf("static user = %#v, calls = %d, error = %v", staticUser, calls.Load(), err)
	}
	staticIssuer, err := resolver.ResolveTrustIssuer(context.Background(), static, "https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	staticTrust, err := resolver.ResolveTrustBindings(context.Background(), static, staticIssuer)
	if err != nil || calls.Load() != 0 || len(staticTrust) != 1 || staticTrust[0].ID != "static-binding" {
		t.Fatalf("static trust = %#v, calls = %d, error = %v", staticTrust, calls.Load(), err)
	}
	dynamic, err := resolver.ResolveClient(context.Background(), "dynamic", false)
	if err != nil || dynamic.source != clientSourceDatabase || calls.Load() != 1 || dynamic.Config.RedirectURIs[0] != "https://dynamic.example/callback" || !dynamic.Config.RefreshTokens.Enabled || dynamic.Config.RequireUserGroupsFromPolicy == nil || *dynamic.Config.RequireUserGroupsFromPolicy {
		t.Fatalf("dynamic = %#v, calls = %d, error = %v", dynamic, calls.Load(), err)
	}
	dynamicUser, err := resolver.ResolveUser(context.Background(), dynamic, "USER@EXAMPLE.COM")
	if err != nil || calls.Load() != 2 || len(dynamicUser.Groups) != 1 || dynamicUser.Groups[0] != "database-group" {
		t.Fatalf("dynamic user = %#v, calls = %d, error = %v", dynamicUser, calls.Load(), err)
	}
	if _, err = resolver.ResolveClient(context.Background(), "dynamic", true); err != nil || calls.Load() != 3 {
		t.Fatalf("fresh resolution calls = %d, error = %v", calls.Load(), err)
	}
}

// TestResolverStaticGroupRequirements verifies global and per-client group policy.
func TestResolverStaticGroupRequirements(t *testing.T) {
	required := true
	notRequired := false
	cfg := &config.Config{
		StaticPolicy: config.StaticPolicyConfig{
			RequireUserGroupsFromPolicy: &required,
			Clients: map[string]config.ClientConfig{
				"required":     {UserGroupMapping: "groups"},
				"not-required": {RequireUserGroupsFromPolicy: &notRequired},
			},
			UserGroupMappings: map[string]map[string][]string{"groups": {}},
		},
	}
	resolver := NewResolver(cfg, nil)
	requiredClient, err := resolver.ResolveClient(context.Background(), "required", false)
	if err != nil {
		t.Fatal(err)
	}
	requiredClient.Config.RequireUserGroupsFromPolicy = &notRequired
	if _, err = resolver.ResolveUser(context.Background(), requiredClient, "user@example.com"); !errors.Is(err, ErrDenied) {
		t.Fatalf("required groups error = %v, want denial", err)
	}
	notRequiredClient, err := resolver.ResolveClient(context.Background(), "not-required", false)
	if err != nil {
		t.Fatal(err)
	}
	user, err := resolver.ResolveUser(context.Background(), notRequiredClient, "user@example.com")
	if err != nil || len(user.Groups) != 0 {
		t.Fatalf("optional groups user = %#v, error = %v", user, err)
	}
}

// TestResolverFreshClientLookupBypassesCache verifies issuance checks observe client removal.
func TestResolverFreshClientLookupBypassesCache(t *testing.T) {
	policyDatabaseConfig := testConfig()
	exists := true
	database := newPostgreSQL(policyDatabaseConfig, nil, nil, func(context.Context, string, ...any) (queryResult, error) {
		return queryResult{columns: []string{"exists"}, rows: [][]any{{exists}}}, nil
	}, nil)
	resolver := NewResolver(&config.Config{PolicyDatabase: &policyDatabaseConfig}, database)
	if _, err := resolver.ResolveClient(context.Background(), "dynamic", false); err != nil {
		t.Fatal(err)
	}
	exists = false
	if _, err := resolver.ResolveClient(context.Background(), "dynamic", false); err != nil {
		t.Fatalf("cached lookup did not preserve the positive result: %v", err)
	}
	if _, err := resolver.ResolveClient(context.Background(), "dynamic", true); !errors.Is(err, ErrDenied) {
		t.Fatalf("fresh lookup error = %v, want denial", err)
	}
}

// TestResolverRejectsInvalidResolvedClient verifies callers cannot use a zero-value handle.
func TestResolverRejectsInvalidResolvedClient(t *testing.T) {
	resolver := NewResolver(&config.Config{}, nil)
	if _, err := resolver.ResolveUser(context.Background(), ResolvedClient{}, "user@example.com"); !IsIndeterminate(err) {
		t.Fatalf("user error = %v, want indeterminate", err)
	}
	if _, err := resolver.ResolveTrustBindings(context.Background(), ResolvedClient{}, ResolvedTrustIssuer{}); !IsIndeterminate(err) {
		t.Fatalf("trust error = %v, want indeterminate", err)
	}
	other := NewResolver(&config.Config{StaticPolicy: config.StaticPolicyConfig{Clients: map[string]config.ClientConfig{"client": {}}}}, nil)
	client, err := other.ResolveClient(context.Background(), "client", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.ResolveUser(context.Background(), client, "user@example.com"); !IsIndeterminate(err) {
		t.Fatalf("foreign client error = %v, want indeterminate", err)
	}
}

// TestResolverDatabasePolicyDoesNotInheritStaticDefaults verifies policy sources remain independent.
func TestResolverDatabasePolicyDoesNotInheritStaticDefaults(t *testing.T) {
	policyDatabaseConfig := testConfig()
	requireUserGroupsFromPolicy := false
	cfg := &config.Config{
		StaticPolicy:   config.StaticPolicyConfig{RequireUserGroupsFromPolicy: &requireUserGroupsFromPolicy},
		PolicyDatabase: &policyDatabaseConfig,
	}
	database := newPostgreSQL(policyDatabaseConfig, nil, nil, func(_ context.Context, query string, _ ...any) (queryResult, error) {
		switch query {
		case "exists":
			return queryResult{columns: []string{"exists"}, rows: [][]any{{true}}}, nil
		case "user":
			return queryResult{columns: []string{"allowed", "groups"}, rows: [][]any{{true, []string{}}}}, nil
		default:
			t.Fatalf("unexpected query %q", query)
			return queryResult{}, nil
		}
	}, nil)
	resolver := NewResolver(cfg, database)
	client, err := resolver.ResolveClient(context.Background(), "dynamic", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.ResolveUser(context.Background(), client, "user@example.com"); !errors.Is(err, ErrDenied) {
		t.Fatalf("user error = %v, want denial", err)
	}
}

// TestResolverPolicyDatabaseTrust verifies database policy is returned in the common effective form.
func TestResolverPolicyDatabaseTrust(t *testing.T) {
	policyDatabaseConfig := testConfig()
	issuerConfig := config.TrustIssuerConfig{Provider: "oidc", IssuerURL: "https://issuer.example", SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}
	cfg := &config.Config{PolicyDatabase: &policyDatabaseConfig, ServiceTokenIssuers: map[string]config.TrustIssuerConfig{"issuer": issuerConfig}}
	database := newPostgreSQL(policyDatabaseConfig, map[string]config.TrustIssuerConfig{"issuer": {Provider: "oidc"}}, nil, func(_ context.Context, query string, _ ...any) (queryResult, error) {
		switch query {
		case "exists":
			return queryResult{columns: []string{"exists"}, rows: [][]any{{true}}}, nil
		case "trust":
			return queryResult{
				columns: []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"},
				rows:    [][]any{{"dynamic", "issuer", "binding", "trusted:user", []byte(`{}`), []byte(`{}`), []byte(`{"repository":{"const":"example/project"}}`), []string{"builders"}}},
			}, nil
		default:
			t.Fatalf("unexpected query %q", query)
			return queryResult{}, nil
		}
	}, nil)
	resolver := NewResolver(cfg, database)
	client, err := resolver.ResolveClient(context.Background(), "dynamic", false)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := resolver.ResolveTrustIssuer(context.Background(), client, issuerConfig.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := resolver.ResolveTrustBindings(context.Background(), client, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].ID != "binding" || bindings[0].Policy != "" || bindings[0].Issuer != "issuer" || bindings[0].Subject != "trusted:user" || len(bindings[0].Groups) != 1 || bindings[0].Groups[0] != "builders" {
		t.Fatalf("bindings = %#v", bindings)
	}
	if err := bindings[0].Schema.Validate(map[string]any{"repository": "example/project"}); err != nil {
		t.Fatalf("effective schema rejected matching claims: %v", err)
	}
}

// TestResolverDynamicTrustIssuer verifies database clients can resolve generic OIDC without allowing static-client fallback.
func TestResolverDynamicTrustIssuer(t *testing.T) {
	policyDatabaseConfig := testConfig()
	database := newPostgreSQL(policyDatabaseConfig, nil, nil, func(_ context.Context, query string, _ ...any) (queryResult, error) {
		switch query {
		case "exists":
			return queryResult{columns: []string{"exists"}, rows: [][]any{{true}}}, nil
		case "issuer":
			return queryResult{
				columns: []string{"issuer_id", "provider", "issuer_url", "signing_algs", "max_token_age_seconds"},
				rows:    [][]any{{"customer-oidc", "oidc", "https://issuer.example", []string{"RS256"}, int64(600)}},
			}, nil
		case "trust":
			return queryResult{
				columns: []string{"client_id", "issuer_id", "binding_id", "subject", "required_claims", "policy_claims", "binding_claims", "groups"},
				rows:    [][]any{{"dynamic", "customer-oidc", "binding", "trusted:user", []byte(`{}`), []byte(`{}`), []byte(`{"tenant":{"const":"acme"}}`), []string{"builders"}}},
			}, nil
		default:
			t.Fatalf("unexpected query %q", query)
			return queryResult{}, nil
		}
	}, nil)
	cfg := &config.Config{
		PolicyDatabase: &policyDatabaseConfig,
		StaticPolicy:   config.StaticPolicyConfig{Clients: map[string]config.ClientConfig{"static": {}}},
	}
	resolver := NewResolver(cfg, database)
	dynamic, err := resolver.ResolveClient(context.Background(), "dynamic", false)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := resolver.ResolveTrustIssuer(context.Background(), dynamic, "https://issuer.example")
	if err != nil || issuer.ID != "customer-oidc" || !issuer.Dynamic {
		t.Fatalf("issuer=%#v error=%v", issuer, err)
	}
	bindings, err := resolver.ResolveTrustBindings(context.Background(), dynamic, issuer)
	if err != nil || len(bindings) != 1 || bindings[0].Issuer != "customer-oidc" {
		t.Fatalf("bindings=%#v error=%v", bindings, err)
	}
	other, err := resolver.ResolveClient(context.Background(), "other", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.ResolveTrustBindings(context.Background(), other, issuer); !IsIndeterminate(err) {
		t.Fatalf("cross-client issuer error=%v, want indeterminate", err)
	}
	static, err := resolver.ResolveClient(context.Background(), "static", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.ResolveTrustIssuer(context.Background(), static, "https://issuer.example"); !errors.Is(err, ErrDenied) {
		t.Fatalf("static client dynamic issuer error=%v, want denial", err)
	}
	if _, err = resolver.ResolveTrustBindings(context.Background(), static, issuer); !IsIndeterminate(err) {
		t.Fatalf("static client reused dynamic issuer error=%v, want indeterminate", err)
	}
	// A static issuer with the same URL must bypass the database issuer query.
	cfg.ServiceTokenIssuers = map[string]config.TrustIssuerConfig{"operator": issuer.Config}
	database.query = func(context.Context, string, ...any) (queryResult, error) {
		t.Fatal("static issuer resolution queried the database")
		return queryResult{}, nil
	}
	issuer, err = resolver.ResolveTrustIssuer(context.Background(), dynamic, "https://issuer.example")
	if err != nil || issuer.ID != "operator" || issuer.Dynamic {
		t.Fatalf("static precedence issuer=%#v error=%v", issuer, err)
	}
}
