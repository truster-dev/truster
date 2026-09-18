// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package refresh

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/tokens"
	"github.com/truster-dev/truster/v2/internal/upstream"
)

const (
	// InvalidGrant means the supplied grant is unusable.
	InvalidGrant = "invalid_grant"
	// InvalidScope means the requested scope exceeds the original grant.
	InvalidScope = "invalid_scope"
	// Temporary means the operation can be retried.
	Temporary = "temporarily_unavailable"
	// maxRefreshMaterialAttempts bounds retries after generated handle collisions.
	maxRefreshMaterialAttempts = 3
	// refreshBusyPollInterval controls how often a concurrent refresh is rechecked.
	refreshBusyPollInterval = 50 * time.Millisecond
	// refreshBusyWait bounds how long a request waits for a concurrent refresh.
	refreshBusyWait = time.Second
)

// policyResolver defines the current client and user decisions consumed by refresh exchange.
type policyResolver interface {
	ResolveClient(context.Context, string, bool) (authpolicy.ResolvedClient, error)
	ResolveUser(context.Context, authpolicy.ResolvedClient, string) (authpolicy.ResolvedUser, error)
}

// Failure is a sanitized refresh exchange failure.
type Failure struct {
	Code                    string
	Description, RetryAfter string
}

// Request contains the protocol-independent refresh request.
type Request struct{ Token, ClientID, Scope string }

// Result contains newly issued rotating token material.
type Result struct {
	AccessToken, IDToken, RefreshToken, Scope, SID, DPoPJKT string
	AccessExpiry                                            time.Time
}

// Service executes refresh grants against current policy and upstream state.
type Service struct {
	cfg            *config.Config
	store          *statedb.Store
	signer         *tokens.Signer
	connectors     map[string]upstream.Connector
	logger         *slog.Logger
	policyResolver policyResolver
}

// NewService creates a refresh exchange service.
func NewService(cfg *config.Config, store *statedb.Store, signer *tokens.Signer, connectors map[string]upstream.Connector, logger *slog.Logger, resolver policyResolver) *Service {
	return &Service{cfg: cfg, store: store, signer: signer, connectors: connectors, logger: logger, policyResolver: resolver}
}

// Exchange validates, narrows, and rotates one refresh grant.
func (s *Service) Exchange(ctx context.Context, req Request) (Result, *Failure) {
	current, err := statedb.ParseRefreshToken(req.Token)
	if err != nil {
		return Result{}, &Failure{Code: InvalidGrant, Description: "refresh token is invalid"}
	}
	now := time.Now().UTC()
	grant, expiry, err := s.store.PrepareRefresh(current, req.ClientID, now)
	if err != nil {
		if errors.Is(err, statedb.ErrRefreshReplay) {
			s.logger.Warn("refresh token replay detected", "client_id", req.ClientID)
			_, _, rotateErr := s.store.RotateRefreshToken(current, statedb.RefreshMaterial{}, req.ClientID, now)
			if rotateErr != nil && !errors.Is(rotateErr, statedb.ErrRefreshReplay) && !errors.Is(rotateErr, statedb.ErrInvalidGrant) {
				return Result{}, &Failure{Code: Temporary, Description: "storage unavailable"}
			}
		}
		if errors.Is(err, statedb.ErrInvalidGrant) || errors.Is(err, statedb.ErrRefreshReplay) {
			return Result{SID: grant.SID}, &Failure{Code: InvalidGrant, Description: "refresh token is invalid"}
		}
		return Result{}, &Failure{Code: Temporary, Description: "storage unavailable"}
	}
	resolved, resolveErr := s.policyResolver.ResolveClient(ctx, grant.ClientID, true)
	if errors.Is(resolveErr, authpolicy.ErrDenied) {
		return Result{SID: grant.SID}, s.revoke(grant, "policy", now)
	}
	if resolveErr != nil {
		return Result{SID: grant.SID}, &Failure{Code: Temporary, Description: "auth temporarily unavailable"}
	}
	client := resolved.Config
	if !client.RefreshTokens.Enabled || grant.Mode == "offline" && !client.RefreshTokens.AllowOfflineAccess {
		return Result{SID: grant.SID}, s.revoke(grant, "policy", now)
	}
	effective, narrowed := grant.Scopes, false
	if requested := strings.Join(strings.Fields(req.Scope), " "); requested != "" {
		allowed := map[string]bool{}
		for _, v := range strings.Fields(grant.Scopes) {
			allowed[v] = true
		}
		for _, v := range strings.Fields(requested) {
			if !allowed[v] {
				return Result{SID: grant.SID}, &Failure{Code: InvalidScope, Description: "scope exceeds original grant"}
			}
		}
		effective, narrowed = requested, requested != grant.Scopes
	}
	user, policyErr := s.policyResolver.ResolveUser(ctx, resolved, grant.Email)
	if errors.Is(policyErr, authpolicy.ErrDenied) {
		return Result{SID: grant.SID}, s.revoke(grant, "policy", now)
	}
	if policyErr != nil {
		return Result{SID: grant.SID}, &Failure{Code: Temporary, Description: "auth temporarily unavailable"}
	}
	groups := user.Groups
	cc, configured := s.cfg.UserLoginConnectors[grant.ConnectorID]
	hasNonce, hasCipher := len(grant.CredentialNonce) != 0, len(grant.CredentialCiphertext) != 0
	if !configured || cc.Type == "email" && (hasNonce || hasCipher) || cc.Type != "email" && (grant.UpstreamSubject == "" || !hasNonce || !hasCipher) {
		return Result{SID: grant.SID}, s.revoke(grant, "connector_provenance", now)
	}
	if cc.Type == "email" {
		return s.direct(current, grant, expiry, effective, narrowed, groups, now)
	}
	return s.connector(ctx, current, grant, effective, narrowed, groups)
}

// direct rotates a direct-email grant without upstream state.
func (s *Service) direct(current statedb.RefreshMaterial, grant statedb.RefreshGrant, expiry time.Time, scopes string, narrowed bool, groups []string, now time.Time) (Result, *Failure) {
	access, id := now.Add(s.cfg.AccessTokenTTL.Duration()), now.Add(s.cfg.IDTokenTTL.Duration())
	if access.After(expiry) {
		access = expiry
	}
	if id.After(expiry) {
		id = expiry
	}
	idToken, accessToken, err := s.signer.SignTokenPair(tokens.TokenContext{Email: grant.Email, EmailVerified: grant.EmailVerified, ClientID: grant.ClientID, Groups: groups, SID: grant.SID, Scopes: scopes, AuthTime: grant.AuthTime, IDExpiry: id, AccessExpiry: access, DPoPJKT: grant.DPoPJKT})
	if err != nil {
		return Result{}, &Failure{Code: Temporary, Description: "token signing failed"}
	}
	var replacement statedb.RefreshMaterial
	for attempt := 0; attempt < maxRefreshMaterialAttempts; attempt++ {
		replacement, err = statedb.GenerateRefreshMaterial()
		if err != nil {
			return Result{}, &Failure{Code: Temporary, Description: "token generation failed"}
		}
		completion := time.Now().UTC()
		if !access.After(completion) || !id.After(completion) {
			return Result{}, &Failure{Code: InvalidGrant, Description: "refresh token is invalid"}
		}
		_, _, err = s.store.RotateRefreshToken(current, replacement, grant.ClientID, completion)
		if !errors.Is(err, statedb.ErrRefreshCollision) {
			break
		}
	}
	if err != nil {
		return Result{}, s.storageError(err)
	}
	result := Result{AccessToken: accessToken, IDToken: idToken, RefreshToken: replacement.Token, SID: grant.SID, AccessExpiry: access, DPoPJKT: grant.DPoPJKT}
	if narrowed {
		result.Scope = scopes
	}
	return result, nil
}

// connector revalidates and atomically persists a connector-backed grant.
func (s *Service) connector(ctx context.Context, current statedb.RefreshMaterial, prepared statedb.RefreshGrant, scopes string, narrowed bool, groups []string) (Result, *Failure) {
	var grant statedb.RefreshGrant
	var claim statedb.RefreshClaim
	var err error
	waitUntil := time.Now().Add(refreshBusyWait)
	for {
		grant, claim, _, err = s.store.ClaimRefresh(current, prepared.ClientID, time.Now().UTC(), 30*time.Second)
		if !errors.Is(err, statedb.ErrRefreshBusy) {
			break
		}
		remaining := time.Until(waitUntil)
		if remaining <= 0 {
			return Result{SID: prepared.SID}, s.storageError(err)
		}
		wait := min(refreshBusyPollInterval, remaining)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Result{SID: prepared.SID}, &Failure{Code: Temporary, Description: "refresh interrupted"}
		case <-timer.C:
		}
	}
	if err != nil {
		if errors.Is(err, statedb.ErrRefreshReplay) {
			s.logger.Warn("refresh token replay detected", "client_id", prepared.ClientID)
		}
		return Result{SID: prepared.SID}, s.storageError(err)
	}
	now := time.Now().UTC()
	release := func() { _ = s.store.ReleaseRefreshClaim(grant.SID, claim) }
	plain, err := statedb.DecryptCredential(current.Secret, grant.SID, grant.ClientID, grant.ConnectorID, grant.CredentialNonce, grant.CredentialCiphertext)
	var credential upstream.Credential
	if err != nil || json.Unmarshal(plain, &credential) != nil {
		return Result{}, s.revoke(grant, "credential", time.Now().UTC())
	}
	connector, ok := s.connectors[grant.ConnectorID]
	if !ok {
		return Result{}, s.revoke(grant, "connector_provenance", time.Now().UTC())
	}
	deadline := claim.ExpiresAt.Add(-5 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	started := false
	refreshCredential := func() *Failure {
		if e := s.store.MarkUpstreamRefreshStarted(grant.SID, claim, time.Now().UTC()); e != nil {
			if errors.Is(e, statedb.ErrCredentialIndeterminate) {
				return s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
			}
			return &Failure{Code: Temporary, Description: "storage unavailable"}
		}
		started = true
		old := credential.RefreshToken
		refreshed, e := connector.Refresh(ctx, &credential)
		if e != nil {
			kind, retry := upstream.ErrorInfo(e)
			if kind == upstream.ErrorConfiguration {
				if a := s.store.AbortUpstreamRefresh(grant.SID, claim); a != nil {
					return &Failure{Code: Temporary, Description: "storage unavailable"}
				}
				return &Failure{Code: Temporary, Description: "upstream configuration error", RetryAfter: retry}
			}
			return s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		if refreshed == nil {
			return s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		credential = *refreshed
		if credential.RefreshToken == "" {
			credential.RefreshToken = old
		}
		return nil
	}
	if !credential.AccessExpiry.IsZero() && !credential.AccessExpiry.After(now.Add(30*time.Second)) {
		if credential.RefreshToken == "" {
			return Result{}, s.revoke(grant, "upstream_expired", now)
		}
		if e := refreshCredential(); e != nil {
			return Result{}, e
		}
	}
	if credential.RefreshToken == "" && credential.AccessExpiry.IsZero() && !credential.AccessNonExpiring {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		return Result{}, s.revoke(grant, "unknown_upstream_expiry", now)
	}
	identity, err := connector.GetIdentity(ctx, credential.OAuthToken())
	if err != nil && !started {
		kind, retry := upstream.ErrorInfo(err)
		if kind == upstream.ErrorUnauthorized && credential.RefreshToken != "" {
			if e := refreshCredential(); e != nil {
				return Result{}, e
			}
			identity, err = connector.GetIdentity(ctx, credential.OAuthToken())
		} else if kind == upstream.ErrorTemporary || kind == upstream.ErrorRateLimit || kind == upstream.ErrorConfiguration {
			release()
			return Result{}, &Failure{Code: Temporary, Description: "upstream unavailable", RetryAfter: retry}
		}
	}
	if err != nil {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		return Result{}, s.revoke(grant, "upstream_authentication", time.Now().UTC())
	}
	matched, providerVerified := false, false
	for _, assertion := range identity.Emails {
		email := strings.ToLower(strings.TrimSpace(assertion.Address))
		if email == grant.Email {
			matched = true
			providerVerified = providerVerified || assertion.Verified
		}
	}
	exists, local, verifyErr := s.store.CredentialVerified(grant.ConnectorID, grant.UpstreamSubject, grant.Email)
	mode := "disabled"
	if s.cfg.Email != nil {
		mode = s.cfg.Email.VerificationMode
	}
	localVerified := exists && local
	verified := providerVerified || localVerified
	accepted := mode == "disabled" || localVerified || mode == "provider" && providerVerified
	if verifyErr != nil {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		release()
		return Result{}, &Failure{Code: Temporary, Description: "storage unavailable"}
	}
	if identity.Subject != grant.UpstreamSubject || !matched || !accepted {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		return Result{}, s.revoke(grant, "identity_mismatch", time.Now().UTC())
	}
	encoded, err := json.Marshal(&credential)
	if err != nil {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		release()
		return Result{}, &Failure{Code: Temporary, Description: "credential encoding failed"}
	}
	issuedAt := time.Now().UTC()
	absolute := grant.AbsoluteExpiry
	if !credential.RefreshExpiry.IsZero() && absolute.After(credential.RefreshExpiry) {
		absolute = credential.RefreshExpiry
	}
	if credential.RefreshToken == "" && !credential.AccessExpiry.IsZero() && absolute.After(credential.AccessExpiry) {
		absolute = credential.AccessExpiry
	}
	expiry := issuedAt.Add(grant.IdleTTL)
	if expiry.After(absolute) {
		expiry = absolute
	}
	access, id := issuedAt.Add(s.cfg.AccessTokenTTL.Duration()), issuedAt.Add(s.cfg.IDTokenTTL.Duration())
	for _, p := range []*time.Time{&access, &id} {
		if p.After(expiry) {
			*p = expiry
		}
		if !credential.AccessExpiry.IsZero() && p.After(credential.AccessExpiry) {
			*p = credential.AccessExpiry
		}
	}
	if !access.After(issuedAt) || !id.After(issuedAt) || !expiry.After(issuedAt) {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		return Result{}, s.revoke(grant, "upstream_expired", issuedAt)
	}
	idToken, accessToken, err := s.signer.SignTokenPair(tokens.TokenContext{Email: grant.Email, EmailVerified: verified, ClientID: grant.ClientID, Groups: groups, SID: grant.SID, Scopes: scopes, AuthTime: grant.AuthTime, IDExpiry: id, AccessExpiry: access, DPoPJKT: grant.DPoPJKT})
	if err != nil {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		release()
		return Result{}, &Failure{Code: Temporary, Description: "token signing failed"}
	}
	grant.UpstreamAccessExpiry, grant.UpstreamRefreshExpiry, grant.UpstreamAccessNonExpiring = credential.AccessExpiry, credential.RefreshExpiry, credential.AccessNonExpiring
	var replacement statedb.RefreshMaterial
	for attempt := 0; attempt < maxRefreshMaterialAttempts; attempt++ {
		replacement, err = statedb.GenerateRefreshMaterial()
		if err != nil {
			break
		}
		nonce, ciphertext, encryptErr := statedb.EncryptCredential(replacement.Secret, grant.SID, grant.ClientID, grant.ConnectorID, encoded)
		if encryptErr != nil {
			err = encryptErr
			break
		}
		completion := time.Now().UTC()
		if !access.After(completion) || !id.After(completion) || !expiry.After(completion) {
			err = statedb.ErrInvalidGrant
			break
		}
		_, err = s.store.CompleteClaimedRefresh(current, replacement, grant, claim, nonce, ciphertext, absolute, completion)
		if !errors.Is(err, statedb.ErrRefreshCollision) {
			break
		}
	}
	if err != nil {
		if started {
			return Result{}, s.revoke(grant, "indeterminate_upstream_credential", time.Now().UTC())
		}
		release()
		return Result{}, s.storageError(err)
	}
	result := Result{AccessToken: accessToken, IDToken: idToken, RefreshToken: replacement.Token, SID: grant.SID, AccessExpiry: access, DPoPJKT: grant.DPoPJKT}
	if narrowed {
		result.Scope = scopes
	}
	return result, nil
}

// revoke revokes a family and returns a sanitized invalid-grant outcome.
func (s *Service) revoke(grant statedb.RefreshGrant, reason string, now time.Time) *Failure {
	if err := s.store.RevokeGrant(grant.SID, grant.ClientID, reason, now.UTC()); err != nil {
		return &Failure{Code: Temporary, Description: "storage unavailable"}
	}
	return &Failure{Code: InvalidGrant, Description: "refresh token is invalid"}
}

// storageError maps storage domain and infrastructure failures.
func (s *Service) storageError(err error) *Failure {
	if errors.Is(err, statedb.ErrInvalidGrant) || errors.Is(err, statedb.ErrRefreshReplay) || errors.Is(err, statedb.ErrCredentialIndeterminate) {
		return &Failure{Code: InvalidGrant, Description: "refresh token is invalid"}
	}
	if errors.Is(err, statedb.ErrRefreshBusy) {
		return &Failure{Code: Temporary, Description: "refresh is already in progress", RetryAfter: "1"}
	}
	return &Failure{Code: Temporary, Description: "storage unavailable"}
}
