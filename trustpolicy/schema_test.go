// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// TestJSONSchema verifies provider definitions accept valid claims and reject unsafe policies.
func TestJSONSchema(t *testing.T) {
	tests := []struct {
		name, provider string
		policy         map[string]any
		valid          bool
	}{
		{name: "github fixed claim", provider: "github", policy: map[string]any{"repository_owner_id": map[string]any{"const": "123"}}, valid: true},
		{name: "github dynamic claim", provider: "github", policy: map[string]any{"repo_property_team": map[string]any{"type": "string"}}, valid: true},
		{name: "github unknown claim", provider: "github", policy: map[string]any{"organization_slug": map[string]any{"const": "acme"}}},
		{name: "buildkite fixed claim", provider: "buildkite", policy: map[string]any{"organization_slug": map[string]any{"const": "acme"}}, valid: true},
		{name: "buildkite dynamic claim", provider: "buildkite", policy: map[string]any{"agent_tag:queue": map[string]any{"const": "deploy"}}, valid: true},
		{name: "oidc custom claim", provider: "oidc", policy: map[string]any{"https://example.com/claims/team": map[string]any{"const": "platform"}}, valid: true},
		{name: "invalid schema", provider: "github", policy: map[string]any{"repository_id": map[string]any{"type": "bogus"}}},
		{name: "prohibited reference", provider: "github", policy: map[string]any{"repository_id": map[string]any{"$ref": "https://attacker.invalid/schema"}}},
	}

	data, err := JSONSchema()
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode generated schema: %v", err)
	}
	location := "https://truster.dev/schema/v2/trust-policy.schema.json"
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(location, document); err != nil {
		t.Fatalf("add generated schema: %v", err)
	}
	root, err := compiler.Compile(location)
	if err != nil {
		t.Fatalf("compile generated schema: %v", err)
	}
	if err := root.Validate(map[string]any{}); err == nil {
		t.Fatal("bundle root accepted a policy without an explicitly selected provider schema")
	}

	compiled := map[string]*jsonschema.Schema{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := compiled[test.provider]
			if schema == nil {
				schema, err = compiler.Compile(fmt.Sprintf("%s#/$defs/%s", location, test.provider))
				if err != nil {
					t.Fatalf("compile %s provider schema: %v", test.provider, err)
				}
				compiled[test.provider] = schema
			}
			err := schema.Validate(test.policy)
			if test.valid != (err == nil) {
				t.Errorf("valid = %v, validation error = %v", test.valid, err)
			}
		})
	}
}

// TestValidateClaims verifies runtime validation uses the same provider and schema rules as the generated bundle.
func TestValidateClaims(t *testing.T) {
	tests := []struct {
		name, provider string
		claims         map[string]json.RawMessage
		valid          bool
	}{
		{name: "GitHub claim", provider: "github", claims: map[string]json.RawMessage{"repository_id": json.RawMessage(`{"const":"123"}`)}, valid: true},
		{name: "GitHub dynamic claim", provider: "github", claims: map[string]json.RawMessage{"repo_property_team": json.RawMessage(`{"type":"string"}`)}, valid: true},
		{name: "Buildkite dynamic claim", provider: "buildkite", claims: map[string]json.RawMessage{"agent_tag:queue": json.RawMessage(`{"const":"deploy"}`)}, valid: true},
		{name: "custom OIDC claim", provider: "oidc", claims: map[string]json.RawMessage{"https://example.com/claims/team": json.RawMessage(`{"const":"platform"}`)}, valid: true},
		{name: "unknown provider", provider: "custom", claims: map[string]json.RawMessage{"sub": json.RawMessage(`{"const":"subject"}`)}},
		{name: "provider mismatch", provider: "github", claims: map[string]json.RawMessage{"pipeline_id": json.RawMessage(`{"const":"123"}`)}},
		{name: "invalid schema", provider: "github", claims: map[string]json.RawMessage{"repository_id": json.RawMessage(`{"type":"bogus"}`)}},
		{name: "external reference", provider: "github", claims: map[string]json.RawMessage{"repository_id": json.RawMessage(`{"$ref":"https://example.com/schema"}`)}},
		{name: "oversized fragment", provider: "github", claims: map[string]json.RawMessage{"repository_id": json.RawMessage(`{"const":"` + strings.Repeat("x", maxSchemaFragmentBytes) + `"}`)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateClaims(test.provider, test.claims)
			if test.valid != (err == nil) {
				t.Errorf("valid = %v, validation error = %v", test.valid, err)
			}
		})
	}
}
