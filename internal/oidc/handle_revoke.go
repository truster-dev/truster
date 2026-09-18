// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/dpop"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/tokens"
)

// HandleRevoke implements client-policy-first, non-enumerating RFC 7009 family revocation.
func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStore(w)
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "form POST is required")
		return
	}
	if media := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); media != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "form content type is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenFormBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		oauthError(w, 400, "invalid_request", "invalid form")
		return
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if err := r.ParseForm(); err != nil || len(r.PostForm["token"]) != 1 || len(r.PostForm["client_id"]) != 1 || r.PostForm.Get("token") == "" || r.PostForm.Get("client_id") == "" {
		oauthError(w, 400, "invalid_request", "token and client_id are required exactly once")
		return
	}
	if _, present := r.PostForm["dpop_jkt"]; present {
		oauthError(w, http.StatusBadRequest, "invalid_request", "dpop_jkt is not accepted at this endpoint")
		return
	}
	clientID := r.PostForm.Get("client_id")
	resolved, err := s.policyResolver.ResolveClient(r.Context(), clientID, false)
	if errors.Is(err, authpolicy.ErrDenied) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid client")
		return
	}
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "policy unavailable")
		return
	}
	proofHeaders := r.Header.Values("DPoP")
	if resolved.Config.DPoP.Mode == "disabled" && len(proofHeaders) != 0 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unexpected DPoP proof")
		return
	}
	if resolved.Config.DPoP.Mode == "required" && len(proofHeaders) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "exactly one DPoP proof is required")
		return
	}
	now := time.Now().UTC()
	var proof *dpop.Proof
	if len(proofHeaders) == 1 {
		proof, err = dpop.ParseAndVerify(proofHeaders[0], resolved.Config.DPoP.SigningAlgorithm, http.MethodPost, config.PublicEndpointURL(s.config.IssuerURL, "revoke"), now)
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "DPoP proof is invalid")
			return
		}
		err = s.reserveDPoP(proof, now)
		if errors.Is(err, dpop.ErrReplay) || errors.Is(err, dpop.ErrReplayCacheFull) {
			s.logDPoPReplay("revoke", clientID)
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "DPoP proof is invalid")
			return
		}
	}
	credential := s.revocationCredential(r.PostForm.Get("token"), clientID)
	proofJKT := ""
	if proof != nil {
		proofJKT = proof.Thumbprint
	}
	err = s.store.RevokeCredential(credential, clientID, proofJKT, "application", now)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "storage unavailable")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// revocationCredential cryptographically identifies refresh, access, or ID token state without a database read.
func (s *Server) revocationCredential(raw, clientID string) statedb.RevocationCredential {
	if material, err := statedb.ParseRefreshToken(raw); err == nil {
		return statedb.RevocationCredential{Refresh: &material}
	}
	token, err := s.signer.VerifyToken(raw)
	if err != nil || len(token.Audience()) != 1 || !tokens.HasAudience(token, clientID) {
		return statedb.RevocationCredential{}
	}
	sidValue, ok := token.Get("sid")
	sid, okString := sidValue.(string)
	if !ok || !okString || sid == "" {
		return statedb.RevocationCredential{}
	}
	jkt, err := tokens.DPoPThumbprint(token)
	if err != nil {
		return statedb.RevocationCredential{}
	}
	_, accessToken := token.Get("scope")
	return statedb.RevocationCredential{SID: sid, TokenJKT: jkt, RequireTokenBinding: accessToken}
}
