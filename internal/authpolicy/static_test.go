// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"errors"
	"slices"
	"testing"

	"github.com/truster-dev/truster/v3/internal/config"
)

// TestResolveStaticUser verifies group lookup, normalization, and requirements.
func TestResolveStaticUser(t *testing.T) {
	required := true
	notRequired := false
	mappings := map[string]map[string][]string{
		"groups": {"user@example.com": {"viewers", "admins", "viewers"}},
	}
	tests := []struct {
		name       string
		global     *bool
		policy     config.ClientConfig
		subject    string
		wantGroups []string
		wantDenied bool
	}{
		{
			name:       "normalizes subject and groups",
			global:     &required,
			policy:     config.ClientConfig{UserGroupMapping: "groups"},
			subject:    " USER@EXAMPLE.COM ",
			wantGroups: []string{"admins", "viewers"},
		},
		{
			name:       "allows empty groups when globally optional",
			global:     &notRequired,
			policy:     config.ClientConfig{UserGroupMapping: "missing"},
			subject:    "user@example.com",
			wantGroups: []string{},
		},
		{
			name:       "client setting overrides global requirement",
			global:     &required,
			policy:     config.ClientConfig{RequireUserGroupsFromPolicy: &notRequired},
			subject:    "user@example.com",
			wantGroups: []string{},
		},
		{
			name:       "denies empty required groups",
			global:     &required,
			policy:     config.ClientConfig{UserGroupMapping: "missing"},
			subject:    "user@example.com",
			wantDenied: true,
		},
		{
			name:       "defaults to requiring groups",
			policy:     config.ClientConfig{},
			subject:    "user@example.com",
			wantDenied: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, err := resolveStaticUser(&config.Config{StaticPolicy: config.StaticPolicyConfig{RequireUserGroupsFromPolicy: test.global, UserGroupMappings: mappings}}, test.policy, test.subject)
			if test.wantDenied {
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("error = %v, want denial", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(user.Groups, test.wantGroups) {
				t.Fatalf("groups = %v, want %v", user.Groups, test.wantGroups)
			}
		})
	}
}

// TestResolveStaticTrust verifies issuer filtering and incomplete binding handling.
func TestResolveStaticTrust(t *testing.T) {
	policy := config.ClientConfig{TrustBindings: []config.TrustBindingConfig{
		{Effective: &config.EffectiveTrustBinding{ID: "matching", Issuer: "issuer"}},
		{Effective: &config.EffectiveTrustBinding{ID: "other", Issuer: "other-issuer"}},
		{},
	}}
	bindings := resolveStaticTrust(policy, "issuer")
	if len(bindings) != 1 || bindings[0].ID != "matching" {
		t.Fatalf("bindings = %#v", bindings)
	}
}
