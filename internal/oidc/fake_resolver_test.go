// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"time"

	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/config"
)

// fakePolicyResolver is a controllable policy decision seam.
type fakePolicyResolver struct {
	client             authpolicy.ResolvedClient
	clientErrors       []error
	userResults        []authpolicy.ResolvedUser
	userErrors         []error
	trust              []config.EffectiveTrustBinding
	trustErr           error
	resolveClientCalls int
	resolveClientFresh []bool
	resolveUserCalls   int
	resolveTrustCalls  int
}

// ResolveClient returns the next configured client result.
func (f *fakePolicyResolver) ResolveClient(_ context.Context, _ string, fresh bool) (authpolicy.ResolvedClient, error) {
	f.resolveClientCalls++
	f.resolveClientFresh = append(f.resolveClientFresh, fresh)
	index := f.resolveClientCalls - 1
	if index < len(f.clientErrors) && f.clientErrors[index] != nil {
		return authpolicy.ResolvedClient{}, f.clientErrors[index]
	}
	return f.client, nil
}

// ResolveUser returns the next configured current-user result.
func (f *fakePolicyResolver) ResolveUser(context.Context, authpolicy.ResolvedClient, string) (authpolicy.ResolvedUser, error) {
	f.resolveUserCalls++
	index := f.resolveUserCalls - 1
	if index < len(f.userErrors) && f.userErrors[index] != nil {
		return authpolicy.ResolvedUser{}, f.userErrors[index]
	}
	if index < len(f.userResults) {
		return f.userResults[index], nil
	}
	return authpolicy.ResolvedUser{}, nil
}

// ResolveTrustIssuer returns a generic test issuer for the exact requested URL.
func (f *fakePolicyResolver) ResolveTrustIssuer(_ context.Context, _ authpolicy.ResolvedClient, issuerURL string) (authpolicy.ResolvedTrustIssuer, error) {
	return authpolicy.ResolvedTrustIssuer{ID: "local", Config: config.TrustIssuerConfig{Provider: "oidc", IssuerURL: issuerURL, SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}}, nil
}

// ResolveTrustBindings returns the configured effective bindings.
func (f *fakePolicyResolver) ResolveTrustBindings(context.Context, authpolicy.ResolvedClient, authpolicy.ResolvedTrustIssuer) ([]config.EffectiveTrustBinding, error) {
	f.resolveTrustCalls++
	return f.trust, f.trustErr
}
