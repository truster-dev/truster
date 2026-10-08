// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0
package oidc

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/challenge"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/dpop"
	"github.com/truster-dev/truster/v3/internal/email"
	"github.com/truster-dev/truster/v3/internal/refresh"
	"github.com/truster-dev/truster/v3/internal/statedb"
	"github.com/truster-dev/truster/v3/internal/templates"
	"github.com/truster-dev/truster/v3/internal/tokens"
	"github.com/truster-dev/truster/v3/internal/trust"
	"github.com/truster-dev/truster/v3/internal/upstream"
	"golang.org/x/time/rate"
)

// policyResolver defines the policy decisions consumed by the OIDC server and its services.
type policyResolver interface {
	ResolveClient(context.Context, string, bool) (authpolicy.ResolvedClient, error)
	ResolveUser(context.Context, authpolicy.ResolvedClient, string) (authpolicy.ResolvedUser, error)
	ResolveTrustIssuer(context.Context, authpolicy.ResolvedClient, string) (authpolicy.ResolvedTrustIssuer, error)
	ResolveTrustBindings(context.Context, authpolicy.ResolvedClient, authpolicy.ResolvedTrustIssuer) ([]config.EffectiveTrustBinding, error)
}

type Server struct {
	config               *config.Config
	connectors           map[string]upstream.Connector
	authCodeMgr          *AuthCodeManager
	signer               *tokens.Signer
	jwksData             []byte
	logger               *slog.Logger
	store                *statedb.Store
	templates            *templates.Manager
	mailer               email.Sender
	challenge            challenge.Verifier
	otpSecret            []byte
	selectionKey         []byte
	encryptionKey        []byte
	refresh              *refresh.Service
	trust                *trust.Service
	policyResolver       policyResolver
	replayOnce           sync.Once
	replayCache          *dpop.ReplayCache
	publicEndpointLimits map[string]*rate.Limiter
}

// NewServer creates an OIDC server with the provided dependencies.
func NewServer(cfg *config.Config, connectors map[string]upstream.Connector, authCodeMgr *AuthCodeManager, signer *tokens.Signer, jwksData []byte, logger *slog.Logger, store *statedb.Store, tm *templates.Manager, mailer email.Sender, challengeVerifier challenge.Verifier, otpSecret, selectionKey, encryptionKey []byte, resolver policyResolver) *Server {
	if resolver == nil {
		resolver = authpolicy.NewResolver(cfg, nil)
	}
	return &Server{config: cfg, connectors: connectors, authCodeMgr: authCodeMgr, signer: signer, jwksData: jwksData, logger: logger, store: store, templates: tm, mailer: mailer, challenge: challengeVerifier, otpSecret: otpSecret, selectionKey: selectionKey, encryptionKey: encryptionKey, policyResolver: resolver, refresh: refresh.NewService(cfg, store, signer, connectors, logger, resolver), trust: trust.NewService(cfg, resolver), publicEndpointLimits: map[string]*rate.Limiter{"/par": rate.NewLimiter(publicEndpointRate, publicEndpointBurst), "/token": rate.NewLimiter(publicEndpointRate, publicEndpointBurst), "/revoke": rate.NewLimiter(publicEndpointRate, publicEndpointBurst)}}
}

// reserveDPoP reserves a proof in this process for the complete acceptance window.
func (s *Server) reserveDPoP(proof *dpop.Proof, now time.Time) error {
	s.replayOnce.Do(func() {
		if s.replayCache == nil {
			s.replayCache = dpop.NewReplayCache(65536)
		}
	})
	return s.replayCache.Reserve(dpop.ReplayHash(proof.Thumbprint, proof.JTI, proof.Method, proof.Target), now)
}

// isValidRedirectURI reports whether a redirect URI exactly matches the client policy.
func (s *Server) isValidRedirectURI(uri string, client config.ClientConfig) bool {
	for _, allowed := range client.RedirectURIs {
		if uri == allowed {
			return true
		}
	}
	return false
}
