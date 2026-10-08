// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/truster-dev/truster/v3/trustpolicy"
)

const maxTrustBindings = 100

var trustNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// ValidTrustBindingID reports whether id satisfies the shared static and dynamic binding identifier contract.
func ValidTrustBindingID(id string) bool { return trustNamePattern.MatchString(id) }

// ValidateDynamicTrustIssuer validates one effective generic OIDC issuer returned by database policy.
func ValidateDynamicTrustIssuer(name string, issuer TrustIssuerConfig) error {
	if !trustNamePattern.MatchString(name) {
		return fmt.Errorf("issuer name %q is invalid", name)
	}
	if issuer.Provider != "oidc" {
		return fmt.Errorf("issuer %q: database policy provider must be oidc", name)
	}
	if err := validateIssuerURL(issuer.IssuerURL); err != nil {
		return fmt.Errorf("issuer %q: %w", name, err)
	}
	u, _ := url.Parse(issuer.IssuerURL)
	if u.Scheme != "https" {
		return fmt.Errorf("issuer %q: database policy issuer_url must use https", name)
	}
	if len(issuer.SigningAlgs) == 0 || issuer.MaxTokenAge.Duration() <= 0 {
		return fmt.Errorf("issuer %q: signing_algs and max_token_age are required", name)
	}
	for _, alg := range issuer.SigningAlgs {
		if !isTrustAlg(alg) {
			return fmt.Errorf("issuer %q: unsupported asymmetric signing algorithm %q", name, alg)
		}
	}
	return nil
}

// TrustIssuerConfig configures external OIDC verification.
type TrustIssuerConfig struct {
	Provider    string   `json:"provider"`
	IssuerURL   string   `json:"issuer_url,omitempty"`
	SigningAlgs []string `json:"signing_algs,omitempty"`
	MaxTokenAge Duration `json:"max_token_age,omitempty"`
}

// TrustPolicyConfig defines reusable claim restrictions and identity output.
type TrustPolicyConfig struct {
	Issuer         string                     `json:"issuer"`
	Subject        string                     `json:"subject,omitempty"`
	Groups         []string                   `json:"groups,omitempty"`
	RequiredClaims map[string]json.RawMessage `json:"required_claims,omitempty"`
	Claims         map[string]json.RawMessage `json:"claims,omitempty"`
}

// TrustBindingConfig allows one policy for a downstream client.
type TrustBindingConfig struct {
	ID          string                     `json:"id"`
	TrustPolicy string                     `json:"trust_policy"`
	Subject     *string                    `json:"subject,omitempty"`
	Groups      []string                   `json:"groups,omitempty"`
	Claims      map[string]json.RawMessage `json:"claims,omitempty"`
	Effective   *EffectiveTrustBinding     `json:"-"`
}

// EffectiveTrustBinding is an immutable startup-compiled auth rule.
type EffectiveTrustBinding struct {
	ID, Policy, Issuer, Subject string
	Groups                      []string
	Schema                      *jsonschema.Schema
}

// validateTrust applies presets, validates inheritance, and compiles every binding schema.
func validateTrust(cfg *Config) error {
	issuerURLs := make(map[string]string, len(cfg.ServiceTokenIssuers))
	for name, issuer := range cfg.ServiceTokenIssuers {
		if !trustNamePattern.MatchString(name) {
			return fmt.Errorf("issuer name %q is invalid", name)
		}
		switch issuer.Provider {
		case "github":
			if issuer.IssuerURL != "" || len(issuer.SigningAlgs) != 0 || issuer.MaxTokenAge != 0 {
				return fmt.Errorf("issuer %q: provider preset fields cannot be overridden", name)
			}
			issuer.IssuerURL, issuer.SigningAlgs, issuer.MaxTokenAge = "https://token.actions.githubusercontent.com", []string{"RS256"}, Duration(10*60*1e9)
		case "buildkite":
			if issuer.IssuerURL != "" || len(issuer.SigningAlgs) != 0 || issuer.MaxTokenAge != 0 {
				return fmt.Errorf("issuer %q: provider preset fields cannot be overridden", name)
			}
			issuer.IssuerURL, issuer.SigningAlgs, issuer.MaxTokenAge = "https://agent.buildkite.com", []string{"RS256"}, Duration(10*60*1e9)
		case "oidc":
			if err := validateIssuerURL(issuer.IssuerURL); err != nil {
				return fmt.Errorf("issuer %q: %w", name, err)
			}
			if len(issuer.SigningAlgs) == 0 || issuer.MaxTokenAge.Duration() <= 0 {
				return fmt.Errorf("issuer %q: signing_algs and max_token_age are required", name)
			}
		default:
			return fmt.Errorf("issuer %q: provider must be github, buildkite, or oidc", name)
		}
		u, _ := url.Parse(issuer.IssuerURL)
		if u.Fragment != "" || u.RawQuery != "" {
			return fmt.Errorf("issuer %q: issuer_url must not contain query or fragment", name)
		}
		for _, alg := range issuer.SigningAlgs {
			if !isTrustAlg(alg) {
				return fmt.Errorf("issuer %q: unsupported asymmetric signing algorithm %q", name, alg)
			}
		}
		if other, exists := issuerURLs[issuer.IssuerURL]; exists {
			return fmt.Errorf("issuers %q and %q have the same effective issuer_url", other, name)
		}
		issuerURLs[issuer.IssuerURL] = name
		cfg.ServiceTokenIssuers[name] = issuer
	}
	for policyName, policy := range cfg.StaticPolicy.TrustPolicies {
		if !trustNamePattern.MatchString(policyName) {
			return fmt.Errorf("policy name %q is invalid", policyName)
		}
		issuer, ok := cfg.ServiceTokenIssuers[policy.Issuer]
		if !ok {
			return fmt.Errorf("policy %q: unknown issuer", policyName)
		}
		if err := validatePolicyFragments(policy, issuer.Provider); err != nil {
			return fmt.Errorf("policy %q: %w", policyName, err)
		}
	}
	for clientID, client := range cfg.StaticPolicy.Clients {
		if len(client.TrustBindings) > maxTrustBindings {
			return fmt.Errorf("client %q: at most %d trust bindings are allowed", clientID, maxTrustBindings)
		}
		seen := map[string]bool{}
		for i := range client.TrustBindings {
			binding := &client.TrustBindings[i]
			if !trustNamePattern.MatchString(binding.ID) || seen[binding.ID] {
				return fmt.Errorf("client %q: trust binding IDs must be nonempty and unique", clientID)
			}
			seen[binding.ID] = true
			policy, ok := cfg.StaticPolicy.TrustPolicies[binding.TrustPolicy]
			if !ok {
				return fmt.Errorf("client %q binding %q: unknown trust_policy", clientID, binding.ID)
			}
			issuer := cfg.ServiceTokenIssuers[policy.Issuer]
			subject := policy.Subject
			if binding.Subject != nil {
				subject = *binding.Subject
			}
			groups := policy.Groups
			if binding.Groups != nil {
				groups = binding.Groups
			}
			if !strings.HasPrefix(subject, "trusted:") || len(subject) > 256 || len(groups) == 0 || len(groups) > 100 {
				return fmt.Errorf("client %q binding %q: effective subject must begin trusted: and groups must contain 1-100 values", clientID, binding.ID)
			}
			for _, group := range groups {
				if group == "" || len(group) > 256 {
					return fmt.Errorf("client %q binding %q: group names must contain 1-256 characters", clientID, binding.ID)
				}
			}
			claims := make(map[string]json.RawMessage, len(policy.Claims)+len(binding.Claims))
			for k, v := range policy.Claims {
				claims[k] = v
			}
			for k, v := range binding.Claims {
				if err := trustpolicy.ValidateClaimName(k, issuer.Provider); err != nil {
					return fmt.Errorf("client %q binding %q: %w", clientID, binding.ID, err)
				}
				claims[k] = v
			}
			schema, err := compileTrustSchema(claims, policy.RequiredClaims)
			if err != nil {
				return fmt.Errorf("client %q binding %q: %w", clientID, binding.ID, err)
			}
			binding.Effective = &EffectiveTrustBinding{ID: binding.ID, Policy: binding.TrustPolicy, Issuer: policy.Issuer, Subject: subject, Groups: append([]string(nil), groups...), Schema: schema}
		}
		cfg.StaticPolicy.Clients[clientID] = client
	}
	return nil
}

// validatePolicyFragments validates every policy fragment before inheritance or overrides are applied.
func validatePolicyFragments(policy TrustPolicyConfig, provider string) error {
	for _, fragments := range []map[string]json.RawMessage{policy.Claims, policy.RequiredClaims} {
		for name := range fragments {
			if err := trustpolicy.ValidateClaimName(name, provider); err != nil {
				return err
			}
		}
	}
	if len(policy.Claims) != 0 || len(policy.RequiredClaims) != 0 {
		if _, err := compileTrustSchema(policy.Claims, policy.RequiredClaims); err != nil {
			return fmt.Errorf("compile policy schema: %w", err)
		}
	}
	return nil
}

// isTrustAlg accepts only asymmetric JWT signature algorithms.
func isTrustAlg(alg string) bool { _, ok := supportedSigningAlgorithms[alg]; return ok }

// compileTrustSchema safely compiles one bounded effective object schema.
func compileTrustSchema(claims, required map[string]json.RawMessage) (*jsonschema.Schema, error) {
	_, schema, err := trustpolicy.CompileSchema(claims, required)
	return schema, err
}
