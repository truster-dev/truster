// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	maxClaimNameLength     = 256
	maxClaims              = 64
	maxSchemaBytes         = 64 << 10
	maxSchemaFragmentBytes = 16 << 10
	maxSchemaDepth         = 16
	maxSchemaMembers       = 64
	maxSchemaItems         = 32
	maxSchemaStringLength  = 4096
)

// providerClaimRule defines one provider's fixed and dynamic claim names.
type providerClaimRule struct {
	claims        map[string]bool
	dynamicPrefix string
	allowAny      bool
}

var standardClaims = map[string]bool{
	"aud": true, "azp": true, "email": true, "email_verified": true, "exp": true, "iat": true,
	"iss": true, "jti": true, "nbf": true, "nonce": true, "sub": true,
}

var providerClaimRules = map[string]providerClaimRule{
	"github": {
		claims:        map[string]bool{"actor": true, "actor_id": true, "base_ref": true, "check_run_id": true, "enterprise": true, "enterprise_id": true, "environment": true, "environment_node_id": true, "event_name": true, "head_ref": true, "issuer_scope": true, "job_workflow_ref": true, "job_workflow_sha": true, "ref": true, "ref_protected": true, "ref_type": true, "repository": true, "repository_id": true, "repository_owner": true, "repository_owner_id": true, "repository_visibility": true, "run_attempt": true, "run_id": true, "run_number": true, "runner_environment": true, "sha": true, "workflow": true, "workflow_ref": true, "workflow_sha": true},
		dynamicPrefix: "repo_property_",
	},
	"buildkite": {
		claims:        map[string]bool{"agent_id": true, "build_branch": true, "build_commit": true, "build_id": true, "build_number": true, "build_source": true, "build_tag": true, "cluster_id": true, "cluster_name": true, "job_id": true, "organization_id": true, "organization_slug": true, "pipeline_id": true, "pipeline_slug": true, "queue_id": true, "queue_key": true, "runner_environment": true, "step_key": true, "https://aws.amazon.com/tags": true},
		dynamicPrefix: "agent_tag:",
	},
	"oidc": {allowAny: true},
}

var prohibitedSchemaKeywords = map[string]bool{
	"$anchor": true, "$dynamicAnchor": true, "$dynamicRef": true, "$id": true, "$recursiveRef": true,
	"$ref": true, "$schema": true, "$vocabulary": true,
}

// denySchemaLoader prevents all external schema retrieval.
type denySchemaLoader struct{}

// Load always rejects external schema retrieval.
func (denySchemaLoader) Load(location string) (any, error) {
	return nil, fmt.Errorf("external schema %q is disabled", location)
}

// ValidateClaimName applies one provider's trust claim allowlist.
func ValidateClaimName(name, provider string) error {
	rule, knownProvider := providerClaimRules[provider]
	dynamicClaim := knownProvider && (rule.allowAny || (rule.dynamicPrefix != "" && strings.HasPrefix(name, rule.dynamicPrefix) && len(name) > len(rule.dynamicPrefix)))
	if name == "" || len(name) > maxClaimNameLength || (!standardClaims[name] && !rule.claims[name] && !dynamicClaim) {
		return fmt.Errorf("claim name %q is not allowed for provider %q", name, provider)
	}
	return nil
}

// ValidateClaims validates and compiles one provider's bounded claim policy.
func ValidateClaims(provider string, claims map[string]json.RawMessage) error {
	if _, ok := providerClaimRules[provider]; !ok {
		return fmt.Errorf("unknown trust provider %q", provider)
	}
	for name := range claims {
		if err := ValidateClaimName(name, provider); err != nil {
			return err
		}
	}
	_, _, err := CompileSchema(claims, nil)
	return err
}

// BuildSchema canonicalizes and validates an effective trust schema without compiling it.
func BuildSchema(claims, required map[string]json.RawMessage) ([]byte, error) {
	properties, names := map[string]any{}, []any{}
	for name, raw := range claims {
		if name == "" || len(name) > maxClaimNameLength {
			return nil, fmt.Errorf("claim name %q is invalid", name)
		}
		var value any
		if err := decodeFragment(raw, &value); err != nil {
			return nil, fmt.Errorf("claim %q: %w", name, err)
		}
		properties[name] = value
		names = append(names, name)
	}
	for name, raw := range required {
		if name == "" || len(name) > maxClaimNameLength {
			return nil, fmt.Errorf("required claim name %q is invalid", name)
		}
		var value any
		if err := decodeFragment(raw, &value); err != nil {
			return nil, fmt.Errorf("required claim %q: %w", name, err)
		}
		if existing, ok := properties[name]; ok {
			properties[name] = map[string]any{"allOf": []any{value, existing}}
		} else {
			properties[name] = value
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i].(string) < names[j].(string) })
	document := map[string]any{"$schema": jsonSchema2020, "type": "object", "required": names, "properties": properties}
	data, _ := json.Marshal(document)
	if len(data) > maxSchemaBytes || len(names) > maxClaims {
		return nil, fmt.Errorf("effective schema exceeds safe limits")
	}
	return data, nil
}

// CompileCanonicalSchema compiles canonical bytes returned by BuildSchema.
func CompileCanonicalSchema(data []byte) (*jsonschema.Schema, error) {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode canonical trust schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(denySchemaLoader{})
	if err := compiler.AddResource("urn:truster:binding", document); err != nil {
		return nil, err
	}
	return compiler.Compile("urn:truster:binding")
}

// CompileSchema canonicalizes and compiles an effective trust schema.
func CompileSchema(claims, required map[string]json.RawMessage) ([]byte, *jsonschema.Schema, error) {
	data, err := BuildSchema(claims, required)
	if err != nil {
		return nil, nil, err
	}
	schema, err := CompileCanonicalSchema(data)
	return data, schema, err
}

// decodeFragment rejects dangerous features and structurally oversized fragments.
func decodeFragment(raw json.RawMessage, value *any) error {
	if len(raw) == 0 || len(raw) > maxSchemaFragmentBytes {
		return fmt.Errorf("schema fragment is empty or too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return inspectSchema(*value, 0)
}

// inspectSchema bounds depth and composition and rejects unsafe schema features.
func inspectSchema(value any, depth int) error {
	if depth > maxSchemaDepth {
		return fmt.Errorf("schema exceeds maximum depth")
	}
	switch value := value.(type) {
	case map[string]any:
		if len(value) > maxSchemaMembers {
			return fmt.Errorf("schema object too large")
		}
		for name, item := range value {
			if prohibitedSchemaKeywords[name] || strings.HasPrefix(name, "content") {
				return fmt.Errorf("prohibited schema keyword %q", name)
			}
			if err := inspectSchema(item, depth+1); err != nil {
				return err
			}
		}
	case []any:
		if len(value) > maxSchemaItems {
			return fmt.Errorf("schema composition or collection too large")
		}
		for _, item := range value {
			if err := inspectSchema(item, depth+1); err != nil {
				return err
			}
		}
	case string:
		if len(value) > maxSchemaStringLength {
			return fmt.Errorf("schema string too long")
		}
	}
	return nil
}
