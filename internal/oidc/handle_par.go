// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/dpop"
	"github.com/truster-dev/truster/v2/internal/statedb"
)

const maxPARBody = 16 << 10

// HandlePAR validates and stores an RFC 9126 pushed authorization request.
func (s *Server) HandlePAR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthJSON(w, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeOAuthJSON(w, 400, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPARBody)
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthJSON(w, 400, "invalid_request")
		return
	}
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeOAuthJSON(w, http.StatusRequestEntityTooLarge, "invalid_request")
			return
		}
		writeOAuthJSON(w, 400, "invalid_request")
		return
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			writeOAuthJSON(w, 400, "invalid_request")
			return
		}
	}
	if len(r.Header.Values("Authorization")) != 0 {
		writeOAuthJSON(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, present := r.PostForm["client_secret"]; present {
		writeOAuthJSON(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, present := r.PostForm["request_uri"]; present {
		writeOAuthJSON(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID := r.PostForm.Get("client_id")
	resolved, err := s.policyResolver.ResolveClient(r.Context(), clientID, false)
	if errors.Is(err, authpolicy.ErrDenied) {
		writeOAuthJSON(w, 400, "invalid_request")
		return
	}
	if err != nil {
		writeOAuthJSON(w, 503, "temporarily_unavailable")
		return
	}
	c := resolved.Config
	redirect := r.PostForm.Get("redirect_uri")
	if redirect == "" || !s.isValidRedirectURI(redirect, c) {
		writeOAuthJSON(w, 400, "invalid_request")
		return
	}
	if r.PostForm.Get("response_type") != "code" || r.PostForm.Get("code_challenge") == "" || r.PostForm.Get("code_challenge_method") != "S256" {
		writeOAuthJSON(w, 400, "invalid_request")
		return
	}
	scopes := strings.Fields(r.PostForm.Get("scope"))
	allowed := map[string]bool{"openid": true, "email": true, "profile": true, "groups": true}
	hasOpenID, offline := false, false
	for _, scope := range scopes {
		hasOpenID = hasOpenID || scope == "openid"
		offline = offline || scope == "offline_access"
		if !allowed[scope] && scope != "offline_access" {
			writeOAuthJSON(w, 400, "invalid_scope")
			return
		}
	}
	if !hasOpenID || offline && (!c.RefreshTokens.Enabled || !c.RefreshTokens.AllowOfflineAccess) {
		writeOAuthJSON(w, 400, "invalid_scope")
		return
	}
	sort.Strings(scopes)
	proofHeaders := r.Header.Values("DPoP")
	if len(proofHeaders) > 1 {
		oauthErr := "invalid_request"
		if c.DPoP.Mode == "required" {
			oauthErr = "invalid_dpop_proof"
		}
		writeOAuthJSON(w, 400, oauthErr)
		return
	}
	thumbprint := r.PostForm.Get("dpop_jkt")
	if values, present := r.PostForm["dpop_jkt"]; present && (len(values) != 1 || values[0] == "") {
		writeOAuthJSON(w, 400, "invalid_request")
		return
	}
	proofPresent := len(proofHeaders) == 1
	selectedJKT, oauthErr := selectDPoP(c.DPoP.Mode, thumbprint, proofPresent)
	if oauthErr != "" {
		writeOAuthJSON(w, 400, string(oauthErr))
		return
	}
	var proof *dpop.Proof
	if proofPresent {
		proof, err = dpop.ParseAndVerify(proofHeaders[0], c.DPoP.SigningAlgorithm, http.MethodPost, config.PublicEndpointURL(s.config.IssuerURL, "par"), time.Now())
		if err != nil || thumbprint != "" && thumbprint != proof.Thumbprint {
			writeOAuthJSON(w, 400, "invalid_dpop_proof")
			return
		}
		selectedJKT = proof.Thumbprint
	}
	requestURIValue, err := statedb.GenerateStateToken()
	if err != nil {
		writeOAuthJSON(w, 503, "temporarily_unavailable")
		return
	}
	requestURI := "urn:ietf:params:oauth:request_uri:" + requestURIValue
	now := time.Now().UTC()
	pushed := &statedb.PushedRequest{RequestURI: requestURI, ClientID: clientID, RedirectURI: redirect, ResponseType: "code", Scopes: strings.Join(scopes, " "), State: r.PostForm.Get("state"), Nonce: r.PostForm.Get("nonce"), CodeChallenge: r.PostForm.Get("code_challenge"), CodeChallengeMethod: "S256", Prompt: r.PostForm.Get("prompt"), DPoPJKT: selectedJKT, CreatedAt: now, ExpiresAt: now.Add(60 * time.Second)}
	if proof != nil {
		err = s.reserveDPoP(proof, now)
	}
	if err == nil {
		err = s.store.SavePushedRequest(pushed)
	}
	if err != nil {
		if errors.Is(err, dpop.ErrReplay) || errors.Is(err, dpop.ErrReplayCacheFull) {
			s.logDPoPReplay("par", clientID)
			writeOAuthJSON(w, 400, "invalid_dpop_proof")
			return
		}
		writeOAuthJSON(w, 503, "temporarily_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": requestURI, "expires_in": 60})
}

// writeOAuthJSON writes a bounded OAuth JSON error response.
func writeOAuthJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`+"\n", code)
}
