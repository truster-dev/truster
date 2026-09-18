// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/dpop"
	"mime"
	"net/http"
	"time"

	refreshdomain "github.com/truster-dev/truster/v2/internal/refresh"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/tokens"
	"github.com/truster-dev/truster/v2/internal/trust"
	"github.com/truster-dev/truster/v2/internal/upstream"
)

const (
	maxTokenFormBytes          = trust.MaxJWTBytes + (4 << 10)
	maxRefreshMaterialAttempts = 3
)

// auditResponseWriter records the final HTTP status for refresh audit logging.
type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader records and forwards an HTTP status.
func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write records an implicit success status and forwards the body.
func (w *auditResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// HandleToken handles the OAuth 2.0 token endpoint (/token).
// It exchanges authorization codes using PKCE or rotates refresh tokens, then issues access and ID tokens.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStore(w)
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST is required")
		return
	}
	if r.URL.RawQuery != "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "OAuth parameters are not accepted in the query")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "form content type is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	for _, name := range []string{"grant_type", "code", "client_id", "client_secret", "redirect_uri", "code_verifier", "refresh_token", "scope", "subject_token", "subject_token_type", "requested_token_type", "dpop_jkt"} {
		if len(r.PostForm[name]) > 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "duplicate parameter")
			return
		}
	}
	if _, present := r.PostForm["dpop_jkt"]; present {
		oauthError(w, http.StatusBadRequest, "invalid_request", "dpop_jkt is not accepted at this endpoint")
		return
	}
	if _, hasClientSecret := r.PostForm["client_secret"]; r.Header.Get("Authorization") != "" || hasClientSecret {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client authentication is not supported")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "":
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	case "authorization_code":
		if r.PostForm.Get("refresh_token") != "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is not valid for this grant type")
			return
		}
		s.exchangeCode(w, r)
	case "refresh_token":
		if r.PostForm.Get("code") != "" || r.PostForm.Get("redirect_uri") != "" || r.PostForm.Get("code_verifier") != "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "authorization code parameters are not valid for this grant type")
			return
		}
		audit := &auditResponseWriter{ResponseWriter: w}
		defer func() {
			if s.logger != nil {
				s.logger.Info("refresh attempt", "status", audit.status, "client_id", r.PostForm.Get("client_id"))
			}
		}()
		if r.PostForm.Get("refresh_token") == "" || r.PostForm.Get("client_id") == "" {
			oauthError(audit, http.StatusBadRequest, "invalid_request", "refresh_token and client_id are required")
			return
		}
		material, inspectErr := statedb.ParseRefreshToken(r.PostForm.Get("refresh_token"))
		if inspectErr != nil {
			oauthError(audit, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
			return
		}
		var inspected statedb.RefreshGrant
		inspected, _, inspectErr = s.store.PrepareRefresh(material, r.PostForm.Get("client_id"), time.Now().UTC())
		if errors.Is(inspectErr, statedb.ErrInvalidGrant) {
			oauthError(audit, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
			return
		}
		if inspectErr != nil && !errors.Is(inspectErr, statedb.ErrRefreshReplay) {
			oauthError(audit, http.StatusServiceUnavailable, "temporarily_unavailable", "storage unavailable")
			return
		}
		resolved, resolveErr := s.policyResolver.ResolveClient(r.Context(), inspected.ClientID, true)
		if errors.Is(resolveErr, authpolicy.ErrDenied) {
			oauthError(audit, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
			return
		}
		if resolveErr != nil {
			oauthError(audit, http.StatusServiceUnavailable, "temporarily_unavailable", "policy unavailable")
			return
		}
		if !validateDPoPBinding(resolved.Config, inspected.DPoPJKT) {
			oauthError(audit, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
			return
		}
		proofHeaders := r.Header.Values("DPoP")
		if inspected.DPoPJKT == "" {
			if len(proofHeaders) != 0 {
				oauthError(audit, 400, "invalid_request", "unexpected DPoP proof")
				return
			}
		} else {
			if len(proofHeaders) != 1 {
				oauthError(audit, 400, "invalid_dpop_proof", "DPoP proof is required")
				return
			}
			proof, proofErr := dpop.ParseAndVerify(proofHeaders[0], resolved.Config.DPoP.SigningAlgorithm, http.MethodPost, config.PublicEndpointURL(s.config.IssuerURL, "token"), time.Now())
			if proofErr != nil {
				oauthError(audit, 400, "invalid_dpop_proof", "DPoP proof is invalid")
				return
			}
			if dpop.VerifyThumbprint(proof, inspected.DPoPJKT) != nil {
				oauthError(audit, 400, "invalid_grant", "refresh token is invalid")
				return
			}
			if reserveErr := s.reserveDPoP(proof, time.Now().UTC()); reserveErr != nil {
				if errors.Is(reserveErr, dpop.ErrReplay) || errors.Is(reserveErr, dpop.ErrReplayCacheFull) {
					s.logDPoPReplay("token", inspected.ClientID)
					oauthError(audit, 400, "invalid_dpop_proof", "DPoP proof is invalid")
				}
				return
			}
		}
		result, exchangeErr := s.refresh.Exchange(r.Context(), refreshdomain.Request{Token: r.PostForm.Get("refresh_token"), ClientID: r.PostForm.Get("client_id"), Scope: r.PostForm.Get("scope")})
		if exchangeErr != nil {
			if exchangeErr.RetryAfter != "" {
				audit.Header().Set("Retry-After", exchangeErr.RetryAfter)
			}
			status := http.StatusBadRequest
			if exchangeErr.Code == refreshdomain.Temporary {
				status = http.StatusServiceUnavailable
			}
			oauthError(audit, status, exchangeErr.Code, exchangeErr.Description)
			return
		}
		tokenType := "Bearer"
		if result.DPoPJKT != "" {
			tokenType = "DPoP"
		}
		response := map[string]any{"access_token": result.AccessToken, "id_token": result.IDToken, "refresh_token": result.RefreshToken, "token_type": tokenType, "expires_in": int64(time.Until(result.AccessExpiry).Seconds())}
		if result.Scope != "" {
			response["scope"] = result.Scope
		}
		oauthJSON(audit, http.StatusOK, response)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		if len(r.Header.Values("DPoP")) != 0 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "DPoP is not supported for token exchange")
			return
		}
		s.exchangeTrustedToken(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
	}
}

// exchangeCode validates and exchanges one authorization code.
func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request) {
	for _, field := range []string{"code", "client_id", "redirect_uri", "code_verifier"} {
		if r.PostForm.Get(field) == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "required parameter missing")
			return
		}
	}
	stored, err := s.authCodeMgr.Peek(r.PostForm.Get("code"))
	if err != nil {
		if errors.Is(err, statedb.ErrInvalidGrant) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		} else {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "storage unavailable")
		}
		return
	}
	if stored.ClientID != r.PostForm.Get("client_id") || stored.RedirectURI != r.PostForm.Get("redirect_uri") || ValidatePKCE(r.PostForm.Get("code_verifier"), stored.CodeChallenge) != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	codeChallenge, _ := pkceChallenge(r.PostForm.Get("code_verifier"))
	binding := statedb.AuthCodeBinding{ClientID: r.PostForm.Get("client_id"), RedirectURI: r.PostForm.Get("redirect_uri"), CodeChallenge: codeChallenge}
	payload := AuthCodePayload{ClientID: stored.ClientID, RedirectURI: stored.RedirectURI, CodeChallenge: stored.CodeChallenge, Email: stored.Email, EmailVerified: stored.EmailVerified, Nonce: stored.Nonce, Scopes: stored.Scopes, RefreshMode: stored.RefreshMode, AuthTime: stored.AuthTime, ConnectorID: stored.ConnectorID, UpstreamSubject: stored.UpstreamSubject, OfflineConsent: stored.OfflineConsent, DPoPJKT: stored.DPoPJKT, PushedAuthorization: stored.PushedAuthorization}
	resolved, resolveErr := s.policyResolver.ResolveClient(r.Context(), payload.ClientID, true)
	if errors.Is(resolveErr, authpolicy.ErrDenied) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	if resolveErr != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "auth temporarily unavailable")
		return
	}
	client := resolved.Config
	if (client.RequirePAR && !payload.PushedAuthorization) || !validateDPoPBinding(client, payload.DPoPJKT) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	proofHeaders := r.Header.Values("DPoP")
	if payload.DPoPJKT == "" && len(proofHeaders) != 0 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unexpected DPoP proof")
		return
	}
	var proof *dpop.Proof
	if payload.DPoPJKT != "" {
		if len(proofHeaders) != 1 {
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "exactly one DPoP proof is required")
			return
		}
		var proofErr error
		proof, proofErr = dpop.ParseAndVerify(proofHeaders[0], client.DPoP.SigningAlgorithm, http.MethodPost, config.PublicEndpointURL(s.config.IssuerURL, "token"), time.Now())
		if proofErr != nil {
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "DPoP proof is invalid")
			return
		}
		if dpop.VerifyThumbprint(proof, payload.DPoPJKT) != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
			return
		}
	}
	if proof != nil {
		if err = s.reserveDPoP(proof, time.Now().UTC()); err != nil {
			if errors.Is(err, dpop.ErrReplay) || errors.Is(err, dpop.ErrReplayCacheFull) {
				s.logDPoPReplay("token", payload.ClientID)
				oauthError(w, 400, "invalid_dpop_proof", "DPoP proof is invalid")
			}
			return
		}
	}
	connectorConfig, connectorExists := s.config.UserLoginConnectors[payload.ConnectorID]
	if payload.RefreshMode != "" && (!client.RefreshTokens.Enabled || !connectorExists || (payload.RefreshMode == "offline" && (!client.RefreshTokens.AllowOfflineAccess || !payload.OfflineConsent))) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	if payload.RefreshMode != "" && connectorConfig.Type != "email" {
		if _, ok := s.connectors[payload.ConnectorID]; !ok {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
			return
		}
	}
	user, policyErr := s.policyResolver.ResolveUser(r.Context(), resolved, payload.Email)
	if errors.Is(policyErr, authpolicy.ErrDenied) {
		oauthError(w, http.StatusForbidden, "access_denied", "user is not allowed")
		return
	}
	if policyErr != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "auth temporarily unavailable")
		return
	}
	groups := user.Groups
	now := time.Now().UTC()
	sid, refresh := "", ""
	accessExpiry, idExpiry := now.Add(s.config.AccessTokenTTL.Duration()), now.Add(s.config.IDTokenTTL.Duration())
	var initialGrant *statedb.RefreshGrant
	var material statedb.RefreshMaterial
	var credentialPlain []byte
	if payload.RefreshMode != "" && client.RefreshTokens.Enabled && connectorExists {
		credentialNonce, credentialCiphertext, credentialErr := s.store.LoadFlowCredential(stored.Code, payload.ClientID, payload.ConnectorID, now)
		credentialBacked := credentialErr == nil
		if credentialErr != nil && !errors.Is(credentialErr, statedb.ErrInvalidGrant) {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "storage unavailable")
			return
		}
		if credentialBacked == (connectorConfig.Type == "email") {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
			return
		}
		sid, err = statedb.GenerateStateToken()
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "token generation failed")
			return
		}
		material, err = statedb.GenerateRefreshMaterial()
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "token generation failed")
			return
		}
		policy := client.RefreshTokens
		idle, absolute := policy.SessionIdleTTL.Duration(), policy.SessionAbsoluteTTL.Duration()
		if payload.RefreshMode == "offline" {
			idle, absolute = policy.OfflineIdleTTL.Duration(), policy.OfflineAbsoluteTTL.Duration()
		}
		absoluteExpiry := payload.AuthTime.Add(absolute)
		grant := statedb.RefreshGrant{SID: sid, ClientID: payload.ClientID, Email: payload.Email, EmailVerified: payload.EmailVerified, Scopes: payload.Scopes, ConnectorID: payload.ConnectorID, UpstreamSubject: payload.UpstreamSubject, Mode: payload.RefreshMode, AuthTime: payload.AuthTime, IdleTTL: idle, AbsoluteExpiry: absoluteExpiry, DPoPJKT: payload.DPoPJKT}
		if credentialBacked {
			plain, loadErr := statedb.DecryptTemporaryCredential(s.encryptionKey, stored.Code, payload.ClientID, payload.ConnectorID, credentialNonce, credentialCiphertext)
			if loadErr != nil {
				oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
				return
			}
			credentialPlain = plain
			var credential upstream.Credential
			if loadErr = json.Unmarshal(plain, &credential); loadErr != nil || credential.RefreshToken == "" && credential.AccessExpiry.IsZero() && !credential.AccessNonExpiring {
				oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
				return
			}
			if !credential.AccessExpiry.IsZero() && credential.RefreshToken == "" && absoluteExpiry.After(credential.AccessExpiry) {
				grant.AbsoluteExpiry = credential.AccessExpiry
			}
			if !credential.RefreshExpiry.IsZero() && grant.AbsoluteExpiry.After(credential.RefreshExpiry) {
				grant.AbsoluteExpiry = credential.RefreshExpiry
			}
			grant.UpstreamAccessExpiry, grant.UpstreamRefreshExpiry, grant.UpstreamAccessNonExpiring = credential.AccessExpiry, credential.RefreshExpiry, credential.AccessNonExpiring
			if !credential.AccessExpiry.IsZero() {
				if accessExpiry.After(credential.AccessExpiry) {
					accessExpiry = credential.AccessExpiry
				}
				if idExpiry.After(credential.AccessExpiry) {
					idExpiry = credential.AccessExpiry
				}
			}
			nonce, ciphertext, loadErr := statedb.EncryptCredential(material.Secret, sid, payload.ClientID, payload.ConnectorID, plain)
			if loadErr != nil {
				oauthError(w, http.StatusInternalServerError, "server_error", "credential encryption failed")
				return
			}
			grant.CredentialNonce, grant.CredentialCiphertext = nonce, ciphertext
		}
		refreshExpiry := now.Add(idle)
		if refreshExpiry.After(grant.AbsoluteExpiry) {
			refreshExpiry = grant.AbsoluteExpiry
		}
		if accessExpiry.After(refreshExpiry) {
			accessExpiry = refreshExpiry
		}
		if idExpiry.After(refreshExpiry) {
			idExpiry = refreshExpiry
		}
		if !refreshExpiry.After(now) || !accessExpiry.After(now) || !idExpiry.After(now) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
			return
		}
		initialGrant = &grant
		refresh = material.Token
	}
	context := tokens.TokenContext{Email: payload.Email, EmailVerified: payload.EmailVerified, ClientID: payload.ClientID, Groups: groups, Nonce: payload.Nonce, SID: sid, Scopes: payload.Scopes, AuthTime: payload.AuthTime, IDExpiry: idExpiry, AccessExpiry: accessExpiry, DPoPJKT: payload.DPoPJKT}
	idToken, accessToken, err := s.signer.SignTokenPair(context)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
	for attempt := 0; ; attempt++ {
		completion := time.Now().UTC()
		if !accessExpiry.After(completion) || !idExpiry.After(completion) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
			return
		}
		err = s.store.ConsumeAuthCode(*stored, binding, initialGrant, material, completion)
		if !errors.Is(err, statedb.ErrRefreshCollision) || attempt+1 == maxRefreshMaterialAttempts {
			break
		}
		material, err = statedb.GenerateRefreshMaterial()
		if err != nil {
			break
		}
		if initialGrant != nil && len(credentialPlain) != 0 {
			initialGrant.CredentialNonce, initialGrant.CredentialCiphertext, err = statedb.EncryptCredential(material.Secret, sid, payload.ClientID, payload.ConnectorID, credentialPlain)
			if err != nil {
				break
			}
		}
		refresh = material.Token
	}
	if err != nil {
		if errors.Is(err, statedb.ErrInvalidGrant) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		} else {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "storage unavailable")
		}
		return
	}
	tokenType := "Bearer"
	if payload.DPoPJKT != "" {
		tokenType = "DPoP"
	}
	response := map[string]any{"access_token": accessToken, "id_token": idToken, "token_type": tokenType, "expires_in": int64(time.Until(accessExpiry).Seconds())}
	if refresh != "" {
		response["refresh_token"] = refresh
	}
	oauthJSON(w, http.StatusOK, response)
}

// setOAuthNoStore applies mandatory OAuth response cache controls.
func setOAuthNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// oauthError writes a non-sensitive OAuth JSON error.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	oauthJSON(w, status, map[string]any{"error": code, "error_description": description})
}

// oauthJSON writes an OAuth JSON object.
func oauthJSON(w http.ResponseWriter, status int, value map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
