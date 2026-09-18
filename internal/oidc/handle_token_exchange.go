// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/tokens"
)

// exchangeTrustedToken verifies an external ID token and issues one downstream ID token.
func (s *Server) exchangeTrustedToken(w http.ResponseWriter, r *http.Request) {
	const idTokenType = "urn:ietf:params:oauth:token-type:id_token"
	allowed := map[string]bool{"grant_type": true, "client_id": true, "subject_token": true, "subject_token_type": true, "requested_token_type": true}
	for name := range r.PostForm {
		if !allowed[name] {
			oauthError(w, http.StatusBadRequest, "invalid_request", "parameter is not valid for token exchange")
			return
		}
	}
	clientID, raw := r.PostForm.Get("client_id"), r.PostForm.Get("subject_token")
	if clientID == "" || raw == "" || r.PostForm.Get("subject_token_type") != idTokenType || r.PostForm.Get("requested_token_type") != idTokenType {
		oauthError(w, http.StatusBadRequest, "invalid_request", "valid token exchange parameters are required")
		return
	}
	if s.trust == nil || s.signer == nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token exchange is unavailable")
		return
	}
	result, err := s.trust.VerifyAndEvaluate(r.Context(), raw, clientID)
	if err != nil {
		if s.logger != nil {
			outcome := "denied"
			if authpolicy.IsIndeterminate(err) && !errors.Is(err, authpolicy.ErrDenied) {
				outcome = "indeterminate"
			}
			attributes := []any{"client_id", clientID, "result", outcome}
			if result != nil {
				attributes = append(attributes, "issuer_id", result.IssuerID, "issuer", result.Issuer)
			}
			s.logger.Info("trust exchange", attributes...)
		}
		if authpolicy.IsIndeterminate(err) && !errors.Is(err, authpolicy.ErrDenied) {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "auth temporarily unavailable")
		} else {
			oauthError(w, http.StatusBadRequest, "invalid_request", "subject token is invalid or unacceptable")
		}
		return
	}
	expiry := time.Now().UTC().Add(s.config.IDTokenTTL.Duration())
	if expiry.After(time.Now().Add(15 * time.Minute)) {
		expiry = time.Now().Add(15 * time.Minute)
	}
	signed, err := s.signer.SignTrustedIDToken(tokens.TrustedTokenContext{Subject: result.Binding.Subject, ClientID: clientID, Groups: result.Binding.Groups, UpstreamIssuer: result.Issuer, UpstreamSubject: result.UpstreamSubject, Expiry: expiry})
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
	if s.logger != nil {
		attributes := []any{"issuer_id", result.IssuerID, "issuer", result.Issuer, "client_id", clientID, "binding", result.Binding.ID, "result", "allowed"}
		if result.Binding.Policy != "" {
			attributes = append(attributes, "policy", result.Binding.Policy)
		}
		for _, claim := range []string{"run_id", "build_id", "job_id"} {
			if value, ok := auditClaim(result.Claims[claim]); ok {
				attributes = append(attributes, claim, value)
			}
		}
		s.logger.Info("trust exchange", attributes...)
	}
	oauthJSON(w, http.StatusOK, map[string]any{"access_token": signed, "issued_token_type": idTokenType, "token_type": "Bearer", "expires_in": int64(time.Until(expiry).Seconds())})
}

// auditClaim returns a bounded scalar provider identifier suitable for structured logging.
func auditClaim(value any) (string, bool) {
	var text string
	switch typed := value.(type) {
	case string:
		text = typed
	case json.Number:
		text = typed.String()
	default:
		return "", false
	}
	return text, text != "" && len(text) <= 256
}
