// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/truster-dev/truster/v2/trustpolicy"
)

// TestCompileTrustSchemaInheritance verifies ordinary overrides remain composed with required policy claims.
func TestCompileTrustSchemaInheritance(t *testing.T) {
	schema, err := compileTrustSchema(
		map[string]json.RawMessage{"shared": json.RawMessage(`{"const":2}`), "ordinary": json.RawMessage(`{"type":"string"}`)},
		map[string]json.RawMessage{"shared": json.RawMessage(`{"type":"integer"}`), "required": json.RawMessage(`{"const":"yes"}`)},
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"valid":             map[string]any{"shared": 2, "ordinary": "x", "required": "yes"},
		"missing ordinary":  map[string]any{"shared": 2, "required": "yes"},
		"required conflict": map[string]any{"shared": "2", "ordinary": "x", "required": "yes"},
	} {
		err := schema.Validate(value)
		if (name == "valid") != (err == nil) {
			t.Errorf("%s: unexpected validation result: %v", name, err)
		}
	}
}

// TestTrustSchemaSafety verifies prohibited keywords, depth, and strict JSON types fail closed.
func TestTrustSchemaSafety(t *testing.T) {
	for _, fragment := range []string{`{"$ref":"https://attacker.invalid/schema"}`, `{"contentEncoding":"base64"}`, `{"$vocabulary":{"x":true}}`, `{"allOf":[{"$schema":"x"}]}`, `{"properties":{"x":{"$id":"x"}}}`, `{"$anchor":"x"}`, `{"$dynamicAnchor":"x"}`} {
		if _, err := compileTrustSchema(map[string]json.RawMessage{"claim": json.RawMessage(fragment)}, nil); err == nil {
			t.Errorf("accepted prohibited fragment %s", fragment)
		}
	}
	schema, err := compileTrustSchema(map[string]json.RawMessage{"n": json.RawMessage(`{"type":"integer","const":1}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(map[string]any{"n": "1"}); err == nil {
		t.Fatal("accepted a JSON string as an integer")
	}
}

// TestTrustRejectsDuplicateIssuersAndInvalidUnusedFragments verifies graph-wide startup validation.
func TestTrustRejectsDuplicateIssuersAndInvalidUnusedFragments(t *testing.T) {
	cfg := benchmarkTrustConfig(1)
	cfg.ServiceTokenIssuers["duplicate"] = cfg.ServiceTokenIssuers["issuer"]
	if err := validateTrust(cfg); err == nil {
		t.Fatal("accepted duplicate effective issuer URL")
	}
	cfg = benchmarkTrustConfig(1)
	cfg.StaticPolicy.TrustPolicies["unused"] = TrustPolicyConfig{Issuer: "issuer", Claims: map[string]json.RawMessage{"sub": json.RawMessage(`{"$id":"forbidden"}`)}}
	if err := validateTrust(cfg); err == nil {
		t.Fatal("accepted prohibited fragment in unused policy")
	}
	cfg = benchmarkTrustConfig(1)
	cfg.StaticPolicy.TrustPolicies["unused"] = TrustPolicyConfig{Issuer: "issuer", Claims: map[string]json.RawMessage{"sub": json.RawMessage(`{"type":"bogus"}`)}}
	if err := validateTrust(cfg); err == nil {
		t.Fatal("accepted invalid schema in unused policy")
	}
	cfg = benchmarkTrustConfig(1)
	policy := cfg.StaticPolicy.TrustPolicies["policy"]
	policy.Claims = map[string]json.RawMessage{"repository_id": json.RawMessage(`{"type":"bogus"}`)}
	cfg.StaticPolicy.TrustPolicies["policy"] = policy
	client := cfg.StaticPolicy.Clients["client"]
	client.TrustBindings[0].Claims = map[string]json.RawMessage{"repository_id": json.RawMessage(`{"const":"1"}`)}
	cfg.StaticPolicy.Clients["client"] = client
	if err := validateTrust(cfg); err == nil {
		t.Fatal("accepted invalid overridden policy schema")
	}
	cfg = benchmarkTrustConfig(1)
	cfg.StaticPolicy.TrustPolicies["policy"] = TrustPolicyConfig{Issuer: "issuer", Subject: "trusted:inherited", Groups: []string{"group"}}
	client = cfg.StaticPolicy.Clients["client"]
	empty := ""
	client.TrustBindings[0].Subject = &empty
	cfg.StaticPolicy.Clients["client"] = client
	if err := validateTrust(cfg); err == nil {
		t.Fatal("explicit empty subject inherited instead of failing")
	}
}

// TestTrustPresetAndEffectiveIdentityValidation verifies preset overrides and empty replacement values are rejected.
func TestTrustPresetAndEffectiveIdentityValidation(t *testing.T) {
	cfg := &Config{ServiceTokenIssuers: map[string]TrustIssuerConfig{"github": {Provider: "github", IssuerURL: "https://evil.invalid"}}}
	if err := validateTrust(cfg); err == nil {
		t.Fatal("accepted a provider preset override")
	}
	cfg = benchmarkTrustConfig(1)
	client := cfg.StaticPolicy.Clients["client"]
	client.TrustBindings[0].Groups = []string{}
	cfg.StaticPolicy.Clients["client"] = client
	if err := validateTrust(cfg); err == nil {
		t.Fatal("accepted explicitly empty effective groups")
	}
	for _, test := range []struct {
		provider, claim string
		allowed         bool
	}{
		{provider: "github", claim: "check_run_id", allowed: true},
		{provider: "github", claim: "repo_property_workspace_id", allowed: true},
		{provider: "github", claim: "repository_unrecognized", allowed: false},
		{provider: "buildkite", claim: "cluster_id", allowed: true},
		{provider: "buildkite", claim: "agent_tag:queue", allowed: true},
		{provider: "buildkite", claim: "unknown", allowed: false},
		{provider: "oidc", claim: "https://example.com/claims/team", allowed: true},
	} {
		err := trustpolicy.ValidateClaimName(test.claim, test.provider)
		if test.allowed != (err == nil) {
			t.Errorf("validateClaimName(%q, %q) error = %v", test.claim, test.provider, err)
		}
	}
	cfg = benchmarkTrustConfig(1)
	client = cfg.StaticPolicy.Clients["client"]
	client.TrustBindings[0].Groups = []string{"system:serviceaccounts/team"}
	cfg.StaticPolicy.Clients["client"] = client
	if err := validateTrust(cfg); err != nil {
		t.Fatalf("rejected valid Kubernetes group name: %v", err)
	}
}

// BenchmarkTrustCandidates measures production schema evaluation at requested candidate counts.
func BenchmarkTrustCandidates(b *testing.B) {
	for _, count := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("bindings_%d", count), func(b *testing.B) {
			cfg := benchmarkTrustConfig(count)
			client := cfg.StaticPolicy.Clients["client"]
			// Compile directly for 1,000 to measure and justify the lower production cap.
			for i := range client.TrustBindings {
				schema, err := compileTrustSchema(map[string]json.RawMessage{"repository_id": json.RawMessage(fmt.Sprintf(`{"const":%q}`, fmt.Sprint(i)))}, nil)
				if err != nil {
					b.Fatal(err)
				}
				client.TrustBindings[i].Effective = &EffectiveTrustBinding{Schema: schema}
			}
			cfg.StaticPolicy.Clients["client"] = client
			claims := map[string]any{"repository_id": "none"}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, binding := range cfg.StaticPolicy.Clients["client"].TrustBindings {
					_ = binding.Effective.Schema.Validate(claims)
				}
			}
		})
	}
}

// benchmarkTrustConfig returns a minimal trust graph with count bindings.
func benchmarkTrustConfig(count int) *Config {
	bindings := make([]TrustBindingConfig, count)
	for i := range bindings {
		bindings[i] = TrustBindingConfig{ID: fmt.Sprintf("binding-%d", i), TrustPolicy: "policy"}
	}
	return &Config{
		ServiceTokenIssuers: map[string]TrustIssuerConfig{"issuer": {Provider: "oidc", IssuerURL: "https://issuer.example", SigningAlgs: []string{"RS256"}, MaxTokenAge: Duration(1)}},
		StaticPolicy: StaticPolicyConfig{
			TrustPolicies: map[string]TrustPolicyConfig{"policy": {Issuer: "issuer", Subject: "trusted:test", Groups: []string{"group"}}},
			Clients:       map[string]ClientConfig{"client": {TrustBindings: bindings}},
		},
	}
}
