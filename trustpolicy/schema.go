// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package trustpolicy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

const jsonSchema2020 = "https://json-schema.org/draft/2020-12/schema"

// JSONSchema returns provider definitions for one claims or required_claims object.
func JSONSchema() ([]byte, error) {
	definitions := schemaDefinitions()
	for provider, rule := range providerClaimRules {
		definitions[provider] = providerSchema(rule)
	}
	document := map[string]any{
		"$schema":     jsonSchema2020,
		"$id":         "https://truster.dev/schema/v2/trust-policy.schema.json",
		"title":       "Truster trust policy schemas",
		"description": "Generated from Truster's runtime trust policy rules. Select $defs/github, $defs/buildkite, or $defs/oidc after resolving the configured issuer's provider.",
		"$comment":    "The bundle root intentionally rejects instances because a bare claims object does not identify its provider.",
		"not":         map[string]any{},
		"$defs":       definitions,
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal trust policy schema: %w", err)
	}
	return append(data, '\n'), nil
}

// providerSchema returns one provider's claim-name and fragment rules.
func providerSchema(rule providerClaimRule) map[string]any {
	fragment := map[string]any{"$ref": "#/$defs/trustSchemaFragment"}
	properties := make(map[string]any, len(standardClaims)+len(rule.claims))
	for name := range standardClaims {
		properties[name] = fragment
	}
	for name := range rule.claims {
		properties[name] = fragment
	}
	schema := map[string]any{
		"description":          "Validates one claims or required_claims object. Final merged-policy validation remains authoritative in Truster.",
		"type":                 "object",
		"maxProperties":        maxClaims,
		"properties":           properties,
		"additionalProperties": false,
	}
	if rule.allowAny {
		schema["propertyNames"] = map[string]any{"minLength": 1, "maxLength": maxClaimNameLength}
		schema["additionalProperties"] = fragment
	} else if rule.dynamicPrefix != "" {
		remaining := maxClaimNameLength - len(rule.dynamicPrefix)
		pattern := fmt.Sprintf(`^%s[\s\S]{1,%d}$`, regexp.QuoteMeta(rule.dynamicPrefix), remaining)
		schema["patternProperties"] = map[string]any{pattern: fragment}
	}
	return schema
}

// schemaDefinitions describes valid JSON Schema fragments and recursive safety limits.
func schemaDefinitions() map[string]any {
	definitions := make(map[string]any, maxSchemaDepth+2)
	definitions["trustSchemaFragment"] = map[string]any{
		"allOf": []any{
			map[string]any{"$ref": jsonSchema2020},
			map[string]any{"$ref": "#/$defs/safeValue0"},
		},
	}
	for depth := 0; depth <= maxSchemaDepth; depth++ {
		definitions[fmt.Sprintf("safeValue%d", depth)] = safeSchemaValue(depth)
	}
	return definitions
}

// safeSchemaValue returns one depth-bounded layer of the JSON value safety schema.
func safeSchemaValue(depth int) map[string]any {
	variants := []any{
		map[string]any{"type": "null"},
		map[string]any{"type": "boolean"},
		map[string]any{"type": "number"},
		map[string]any{"type": "string", "maxLength": maxSchemaStringLength},
	}
	arraySchema := map[string]any{"type": "array", "maxItems": maxSchemaItems}
	objectSchema := map[string]any{
		"type":          "object",
		"maxProperties": maxSchemaMembers,
		"propertyNames": map[string]any{
			"not": map[string]any{
				"anyOf": []any{
					map[string]any{"enum": sortedSchemaKeywords()},
					map[string]any{"pattern": "^content"},
				},
			},
		},
	}
	if depth == maxSchemaDepth {
		arraySchema["maxItems"] = 0
		objectSchema["maxProperties"] = 0
	} else {
		next := map[string]any{"$ref": fmt.Sprintf("#/$defs/safeValue%d", depth+1)}
		arraySchema["items"] = next
		objectSchema["additionalProperties"] = next
	}
	return map[string]any{"oneOf": append(variants, arraySchema, objectSchema)}
}

// sortedSchemaKeywords returns prohibited keywords in deterministic order.
func sortedSchemaKeywords() []string {
	keywords := make([]string, 0, len(prohibitedSchemaKeywords))
	for keyword := range prohibitedSchemaKeywords {
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	return keywords
}
