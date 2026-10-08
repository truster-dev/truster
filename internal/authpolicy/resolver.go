// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"context"
	"errors"

	"github.com/truster-dev/truster/v2/internal/config"
)

// clientSource identifies the resolver-owned implementation for a client.
type clientSource uint8

const (
	clientSourceStatic clientSource = iota + 1
	clientSourceDatabase
)

// ResolvedClient contains effective client policy and resolver-owned identity.
type ResolvedClient struct {
	Config config.ClientConfig
	id     string
	source clientSource
	owner  *Resolver
}

// ResolvedUser contains the effective current groups for a user.
type ResolvedUser struct{ Groups []string }

// ResolvedTrustIssuer contains effective issuer verification policy and resolver-owned identity.
type ResolvedTrustIssuer struct {
	ID       string
	Config   config.TrustIssuerConfig
	Dynamic  bool
	clientID string
	owner    *Resolver
}

// Resolver gives static clients deterministic precedence over database policy.
type Resolver struct {
	cfg            *config.Config
	policyDatabase *PostgreSQL
}

// NewResolver combines static configuration with an optional policy database.
func NewResolver(cfg *config.Config, policyDatabase *PostgreSQL) *Resolver {
	return &Resolver{cfg: cfg, policyDatabase: policyDatabase}
}

// ResolveClient resolves effective policy for a client supplied by static or database policy.
// Fresh bypasses the existence cache for required pre-issuance checks.
func (r *Resolver) ResolveClient(ctx context.Context, clientID string, fresh bool) (ResolvedClient, error) {
	if r == nil || r.cfg == nil {
		return ResolvedClient{}, &IndeterminateError{Err: errors.New("policy resolver unavailable")}
	}
	if client, ok := r.cfg.StaticPolicy.Clients[clientID]; ok {
		if len(client.RedirectURIs) == 0 {
			client.RedirectURIs = append([]string(nil), r.cfg.StaticPolicy.DefaultRedirectURIs...)
		}
		return ResolvedClient{Config: client, id: clientID, source: clientSourceStatic, owner: r}, nil
	}
	if !validDynamicClientID(clientID) {
		return ResolvedClient{}, ErrDenied
	}
	if r.policyDatabase == nil || r.cfg.PolicyDatabase == nil {
		return ResolvedClient{}, ErrDenied
	}
	var exists bool
	var err error
	if fresh {
		exists, err = r.policyDatabase.clientExists(ctx, clientID, false)
	} else {
		exists, err = r.policyDatabase.ClientExists(ctx, clientID)
	}
	if err != nil {
		return ResolvedClient{}, err
	}
	if !exists {
		return ResolvedClient{}, ErrDenied
	}
	defaults := r.cfg.PolicyDatabase.ClientDefaults
	return ResolvedClient{id: clientID, source: clientSourceDatabase, owner: r, Config: config.ClientConfig{
		RedirectURIs:                append([]string(nil), r.cfg.PolicyDatabase.RedirectURIs...),
		RequireUserGroupsFromPolicy: defaults.RequireUserGroupsFromPolicy,
		RefreshTokens:               defaults.RefreshTokens,
		DPoP:                        defaults.DPoP,
		RequirePAR:                  defaults.RequirePAR,
	}}, nil
}

// ResolveUser returns effective current user policy without exposing its storage.
func (r *Resolver) ResolveUser(ctx context.Context, client ResolvedClient, subject string) (ResolvedUser, error) {
	if r == nil || r.cfg == nil {
		return ResolvedUser{}, &IndeterminateError{Err: errors.New("policy resolver unavailable")}
	}
	if client.owner != r {
		return ResolvedUser{}, &IndeterminateError{Err: errors.New("invalid resolved client")}
	}
	switch client.source {
	case clientSourceStatic:
		policy, ok := r.cfg.StaticPolicy.Clients[client.id]
		if !ok {
			return ResolvedUser{}, &IndeterminateError{Err: errors.New("resolved client policy unavailable")}
		}
		return resolveStaticUser(r.cfg, policy, subject)
	case clientSourceDatabase:
		if r.policyDatabase == nil || r.cfg.PolicyDatabase == nil {
			return ResolvedUser{}, &IndeterminateError{Err: errors.New("policy database unavailable")}
		}
		defaults := r.cfg.PolicyDatabase.ClientDefaults
		policy := config.ClientConfig{RequireUserGroupsFromPolicy: defaults.RequireUserGroupsFromPolicy}
		return r.policyDatabase.ResolveUser(ctx, client.id, subject, policy.ShouldRequireUserGroupsFromPolicy(nil))
	default:
		return ResolvedUser{}, &IndeterminateError{Err: errors.New("invalid resolved client")}
	}
}

// ResolveTrustIssuer resolves an exact token issuer without trusting unverified token claims as configuration.
func (r *Resolver) ResolveTrustIssuer(ctx context.Context, client ResolvedClient, issuerURL string) (ResolvedTrustIssuer, error) {
	if r == nil || r.cfg == nil {
		return ResolvedTrustIssuer{}, &IndeterminateError{Err: errors.New("policy resolver unavailable")}
	}
	if client.owner != r {
		return ResolvedTrustIssuer{}, &IndeterminateError{Err: errors.New("invalid resolved client")}
	}
	for id, issuer := range r.cfg.ServiceTokenIssuers {
		if issuer.IssuerURL == issuerURL {
			return ResolvedTrustIssuer{ID: id, Config: issuer, clientID: client.id, owner: r}, nil
		}
	}
	if client.source != clientSourceDatabase {
		return ResolvedTrustIssuer{}, ErrDenied
	}
	if r.policyDatabase == nil {
		return ResolvedTrustIssuer{}, &IndeterminateError{Err: errors.New("policy database unavailable")}
	}
	id, issuer, err := r.policyDatabase.ResolveTrustIssuer(ctx, client.id, issuerURL)
	if err != nil {
		return ResolvedTrustIssuer{}, err
	}
	return ResolvedTrustIssuer{ID: id, Config: issuer, Dynamic: true, clientID: client.id, owner: r}, nil
}

// ResolveTrustBindings returns effective trust bindings for a client and resolved issuer.
func (r *Resolver) ResolveTrustBindings(ctx context.Context, client ResolvedClient, issuer ResolvedTrustIssuer) ([]config.EffectiveTrustBinding, error) {
	if r == nil || r.cfg == nil {
		return nil, &IndeterminateError{Err: errors.New("policy resolver unavailable")}
	}
	if client.owner != r || issuer.owner != r || issuer.clientID != client.id {
		return nil, &IndeterminateError{Err: errors.New("invalid resolved trust issuer")}
	}
	switch client.source {
	case clientSourceStatic:
		policy, ok := r.cfg.StaticPolicy.Clients[client.id]
		if !ok {
			return nil, &IndeterminateError{Err: errors.New("resolved client policy unavailable")}
		}
		return resolveStaticTrust(policy, issuer.ID), nil
	case clientSourceDatabase:
		if r.policyDatabase == nil {
			return nil, &IndeterminateError{Err: errors.New("policy database unavailable")}
		}
		compiled, err := r.policyDatabase.ResolveTrustBindings(ctx, client.id, issuer.ID, issuer.Config)
		if err != nil {
			return nil, err
		}
		bindings := make([]config.EffectiveTrustBinding, 0, len(compiled))
		for _, binding := range compiled {
			bindings = append(bindings, config.EffectiveTrustBinding{ID: binding.ID, Issuer: issuer.ID, Subject: binding.Subject, Groups: binding.Groups, Schema: binding.Schema})
		}
		return bindings, nil
	default:
		return nil, &IndeterminateError{Err: errors.New("invalid resolved client")}
	}
}
