// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/upstream"
)

// HandleCallback handles an OAuth callback and selects or accepts an upstream email.
func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("error") != "" {
		http.Error(w, "upstream authorization failed", 400)
		return
	}
	stateToken := r.URL.Query().Get("state")
	state, err := s.authCodeMgr.PeekState(stateToken)
	if err != nil {
		http.Error(w, "invalid state", 400)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/callback/")
	if id == "" || id != state.ConnectorID {
		http.Error(w, "connector does not match state", 400)
		return
	}
	connector, ok := s.connectors[id]
	if !ok {
		http.Error(w, "unknown connector", 400)
		return
	}
	token, err := connector.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		s.logger.Error("authorization exchange failed", "connector_id", id, "error", err)
		http.Error(w, "authorization exchange failed", http.StatusBadGateway)
		return
	}
	if state.RefreshMode != "" {
		credential, marshalErr := json.Marshal(token)
		if marshalErr != nil || len(s.encryptionKey) != 32 {
			http.Error(w, "credential persistence unavailable", http.StatusInternalServerError)
			return
		}
		nonce, ciphertext, encryptErr := statedb.EncryptTemporaryCredential(s.encryptionKey, stateToken, state.ClientID, id, credential)
		if encryptErr != nil || s.store.SaveFlowCredential("", stateToken, state.ClientID, id, nonce, ciphertext, time.Now().Add(10*time.Minute)) != nil {
			http.Error(w, "credential persistence unavailable", http.StatusInternalServerError)
			return
		}
	}
	identity, err := connector.GetIdentity(r.Context(), token.OAuthToken())
	if err != nil {
		http.Error(w, "identity lookup failed", http.StatusBadGateway)
		return
	}
	if strings.TrimSpace(identity.Subject) == "" || len(identity.Emails) == 0 {
		http.Error(w, "invalid upstream identity", http.StatusBadGateway)
		return
	}
	if len(identity.Emails) > 1 {
		s.renderIdentitySelection(w, stateToken, id, identity)
		return
	}
	state, err = s.authCodeMgr.DecodeState(stateToken)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	s.acceptOrChallenge(w, r, *state, id, identity.Subject, identity.Emails[0])
}

// acceptOrChallenge accepts a verified identity or starts local email verification.
func (s *Server) acceptOrChallenge(w http.ResponseWriter, r *http.Request, state OAuthState, id, subject string, emailAssertion upstream.Email) {
	if strings.TrimSpace(subject) == "" {
		http.Error(w, "invalid upstream identity", http.StatusBadGateway)
		return
	}
	email, err := normalizeEmail(emailAssertion.Address)
	if err != nil {
		http.Error(w, "invalid upstream identity", http.StatusBadGateway)
		return
	}
	exists, local, err := s.store.CredentialVerified(id, subject, email)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	mode := "disabled"
	if s.config.Email != nil {
		mode = s.config.Email.VerificationMode
	}
	accepted := verificationAccepted(mode, emailAssertion.Verified, local)
	if accepted {
		if !exists || emailAssertion.Verified {
			if err = s.store.SaveCredential(id, subject, email, local, time.Now()); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		s.complete(w, r, state, subject, email, local || emailAssertion.Verified)
		return
	}
	if s.config.Email == nil || s.mailer == nil {
		http.Error(w, "email verification unavailable", http.StatusForbidden)
		return
	}
	s.beginOTP(w, r, state, id, subject, email)
}

// verificationAccepted reports whether verification evidence satisfies the configured mode.
func verificationAccepted(mode string, providerVerified, localVerified bool) bool {
	return mode == "disabled" || localVerified || (mode == "provider" && providerVerified)
}

// complete issues an authorization code and redirects to the client.
func (s *Server) complete(w http.ResponseWriter, r *http.Request, state OAuthState, subject, email string, emailVerified bool) {
	if state.Purpose == "manage_grants" {
		s.renderGrants(w, email)
		return
	}
	resolved, err := s.policyResolver.ResolveClient(r.Context(), state.ClientID, true)
	if err != nil {
		if errors.Is(err, authpolicy.ErrDenied) {
			s.renderErrorPage(w, http.StatusForbidden, "Login Failed", "Your account was not allowed.")
		} else {
			http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	if !s.isValidRedirectURI(state.RedirectURI, resolved.Config) {
		http.Error(w, "authorization profile changed", http.StatusBadRequest)
		return
	}
	if !stateSatisfiesClientPolicy(&state, resolved.Config) || state.RefreshMode == "offline" && !state.OfflineConsent {
		redirectAuthorizationError(w, r, state.RedirectURI, state.OIDCState, "invalid_request")
		return
	}
	_, policyErr := s.policyResolver.ResolveUser(r.Context(), resolved, strings.ToLower(email))
	if policyErr != nil {
		if errors.Is(policyErr, authpolicy.ErrDenied) {
			s.renderErrorPage(w, http.StatusForbidden, "Login Failed", "Your account was not allowed.")
		} else {
			http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	connectorConfig, connectorConfigured := s.config.UserLoginConnectors[state.ConnectorID]
	credentialBacked := false
	var credential []byte
	if state.RefreshMode != "" && state.FlowID != "" {
		nonce, ciphertext, loadErr := s.store.LoadFlowCredential(state.FlowID, state.ClientID, state.ConnectorID, time.Now().UTC())
		if loadErr == nil {
			credentialBacked = true
			credential, loadErr = statedb.DecryptTemporaryCredential(s.encryptionKey, state.FlowID, state.ClientID, state.ConnectorID, nonce, ciphertext)
		}
		if loadErr != nil && !errors.Is(loadErr, statedb.ErrInvalidGrant) {
			http.Error(w, "internal error", 500)
			return
		}
	}
	if state.RefreshMode != "" && (!connectorConfigured || credentialBacked == (connectorConfig.Type == "email")) {
		http.Error(w, "authorization flow is invalid", http.StatusBadRequest)
		return
	}
	code, err := s.authCodeMgr.GenerateCode(AuthCodePayload{ClientID: state.ClientID, RedirectURI: state.RedirectURI, CodeChallenge: state.CodeChallenge, Email: email, EmailVerified: emailVerified, Nonce: state.Nonce, Scopes: state.Scopes, RefreshMode: state.RefreshMode, AuthTime: state.AuthTime, ConnectorID: state.ConnectorID, UpstreamSubject: subject, OfflineConsent: state.OfflineConsent, DPoPJKT: state.DPoPJKT, PushedAuthorization: state.PushedAuthorization})
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	if credentialBacked {
		nonce, ciphertext, saveErr := statedb.EncryptTemporaryCredential(s.encryptionKey, code, state.ClientID, state.ConnectorID, credential)
		if saveErr != nil || s.store.SaveFlowCredential(state.FlowID, code, state.ClientID, state.ConnectorID, nonce, ciphertext, time.Now().UTC().Add(5*time.Minute)) != nil {
			http.Error(w, "internal error", 500)
			return
		}
	}
	u, _ := url.Parse(state.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if state.OIDCState != "" {
		q.Set("state", state.OIDCState)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
