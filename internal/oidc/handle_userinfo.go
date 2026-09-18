// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/dpop"
	"github.com/truster-dev/truster/v2/internal/tokens"
)

// accessAuthError is a bounded protected-resource authentication failure.
type accessAuthError struct {
	status            int
	scheme, code, alg string
}

// authenticateAccessToken is the shared verifier boundary for access-token resources.
func (s *Server) authenticateAccessToken(r *http.Request, endpoint string) (jwt.Token, *accessAuthError) {
	auth, proofs := r.Header.Values("Authorization"), r.Header.Values("DPoP")
	attemptedScheme := "Bearer"
	if len(auth) != 0 {
		fields := strings.Fields(auth[0])
		if len(fields) != 0 && strings.EqualFold(fields[0], "DPoP") {
			attemptedScheme = "DPoP"
		}
	}
	if len(auth) > 1 || len(proofs) > 1 {
		return nil, &accessAuthError{status: 400, scheme: attemptedScheme, code: "invalid_request"}
	}
	if len(auth) == 0 {
		return nil, &accessAuthError{status: 401, scheme: "Bearer"}
	}
	parts := strings.Fields(auth[0])
	if len(parts) != 2 {
		return nil, &accessAuthError{status: 400, scheme: attemptedScheme, code: "invalid_request"}
	}
	scheme, raw := parts[0], parts[1]
	if !strings.EqualFold(scheme, "Bearer") && !strings.EqualFold(scheme, "DPoP") {
		return nil, &accessAuthError{status: 400, scheme: "Bearer", code: "invalid_request"}
	}
	token, err := s.signer.VerifyAccessToken(raw)
	if err != nil {
		return nil, &accessAuthError{status: 401, scheme: scheme, code: "invalid_token"}
	}
	jkt, err := tokens.DPoPThumbprint(token)
	if err != nil {
		return nil, &accessAuthError{status: 401, scheme: scheme, code: "invalid_token"}
	}
	if jkt == "" {
		if !strings.EqualFold(scheme, "Bearer") || len(proofs) != 0 {
			return nil, &accessAuthError{status: 401, scheme: scheme, code: "invalid_token"}
		}
		return token, nil
	}
	if !strings.EqualFold(scheme, "DPoP") {
		return nil, &accessAuthError{status: 401, scheme: "Bearer", code: "invalid_token"}
	}
	if len(proofs) != 1 {
		return nil, &accessAuthError{status: 401, scheme: "DPoP", code: "invalid_dpop_proof", alg: supportedDPoPAlgorithmChallenge}
	}
	proof, err := dpop.ParseAndVerifyBound(proofs[0], r.Method, config.PublicEndpointURL(s.config.IssuerURL, endpoint), time.Now())
	if err != nil || dpop.VerifyAccessTokenHash(proof, raw) != nil {
		return nil, &accessAuthError{status: 401, scheme: "DPoP", code: "invalid_dpop_proof", alg: supportedDPoPAlgorithmChallenge}
	}
	if dpop.VerifyThumbprint(proof, jkt) != nil {
		return nil, &accessAuthError{status: 401, scheme: "DPoP", code: "invalid_token", alg: supportedDPoPAlgorithmChallenge}
	}
	err = s.reserveDPoP(proof, time.Now().UTC())
	if errors.Is(err, dpop.ErrReplay) || errors.Is(err, dpop.ErrReplayCacheFull) {
		clientID := ""
		if audience := token.Audience(); len(audience) == 1 {
			clientID = audience[0]
		}
		s.logDPoPReplay("userinfo", clientID)
		return nil, &accessAuthError{status: 401, scheme: "DPoP", code: "invalid_dpop_proof", alg: supportedDPoPAlgorithmChallenge}
	}
	return token, nil
}

// writeAccessAuthError writes a standards-shaped protected-resource challenge.
func writeAccessAuthError(w http.ResponseWriter, failure *accessAuthError) {
	challenge := failure.scheme
	if failure.code != "" {
		challenge += ` error="` + failure.code + `"`
	}
	if failure.scheme == "DPoP" {
		algs := failure.alg
		if algs == "" {
			algs = supportedDPoPAlgorithmChallenge
		}
		challenge += `, algs="` + algs + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(failure.status)
}

// HandleUserInfo handles the OIDC userinfo endpoint through the shared access verifier.
func (s *Server) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	token, failure := s.authenticateAccessToken(r, "userinfo")
	if failure != nil {
		writeAccessAuthError(w, failure)
		return
	}
	scope, _ := token.Get("scope")
	if !slices.Contains(strings.Fields(fmt.Sprint(scope)), "openid") {
		scheme := "Bearer"
		alg := ""
		if jkt, _ := tokens.DPoPThumbprint(token); jkt != "" {
			scheme, alg = "DPoP", supportedDPoPAlgorithmChallenge
		}
		writeAccessAuthError(w, &accessAuthError{status: http.StatusForbidden, scheme: scheme, code: "insufficient_scope", alg: alg})
		return
	}
	userInfo := map[string]interface{}{"sub": token.Subject()}
	for _, claim := range []string{"email", "email_verified", "preferred_username", "groups"} {
		if value, ok := token.Get(claim); ok {
			userInfo[claim] = value
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil && s.logger != nil {
		s.logger.Error("failed to encode userinfo response", "error", err)
	}
}
