// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
)

// oauthAuthorizationError identifies an OAuth authorization endpoint error code.
type oauthAuthorizationError string

const (
	oauthAuthorizationErrorAccessDenied            oauthAuthorizationError = "access_denied"
	oauthAuthorizationErrorConsentRequired         oauthAuthorizationError = "consent_required"
	oauthAuthorizationErrorInvalidRequest          oauthAuthorizationError = "invalid_request"
	oauthAuthorizationErrorInvalidScope            oauthAuthorizationError = "invalid_scope"
	oauthAuthorizationErrorLoginRequired           oauthAuthorizationError = "login_required"
	oauthAuthorizationErrorServer                  oauthAuthorizationError = "server_error"
	oauthAuthorizationErrorTemporarilyUnavailable  oauthAuthorizationError = "temporarily_unavailable"
	oauthAuthorizationErrorUnsupportedResponseType oauthAuthorizationError = "unsupported_response_type"
)

// HandleAuthorize validates a downstream authorization request and starts connector selection.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if requestURIs, present := q["request_uri"]; present {
		if len(q) != 2 || len(q["client_id"]) != 1 || len(requestURIs) != 1 || q.Get("client_id") == "" || requestURIs[0] == "" {
			s.renderBrowserError(w, http.StatusBadRequest, failureInvalidPushedAuthorizationRequest)
			return
		}
		s.handlePushedAuthorize(w, r, q.Get("client_id"), requestURIs[0])
		return
	}
	clientID := q.Get("client_id")
	if len(q["client_id"]) != 1 || len(q["redirect_uri"]) != 1 {
		s.renderBrowserError(w, http.StatusBadRequest, failureInvalidAuthorizationRequest)
		return
	}
	resolved, err := s.policyResolver.ResolveClient(r.Context(), clientID, false)
	if errors.Is(err, authpolicy.ErrDenied) {
		s.renderBrowserError(w, http.StatusBadRequest, failureUnknownClient)
		return
	}
	if err != nil {
		s.renderBrowserError(w, http.StatusServiceUnavailable, failureClientPolicyUnavailable)
		return
	}
	client := resolved.Config
	if client.RequirePAR {
		s.renderBrowserError(w, http.StatusBadRequest, failurePushedAuthorizationRequired)
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" || !s.isValidRedirectURI(redirect, client) {
		s.renderBrowserError(w, http.StatusBadRequest, failureInvalidRedirectURI)
		return
	}
	for _, values := range q {
		if len(values) != 1 {
			s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorInvalidRequest, failureAuthorizationParameterDuplicate)
			return
		}
	}
	if len(r.Header.Values("DPoP")) != 0 {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorInvalidRequest, failureAuthorizationDPoPHeaderUnexpected)
		return
	}
	dpopJKT := q.Get("dpop_jkt")
	if values, present := q["dpop_jkt"]; present && (len(values) != 1 || values[0] == "") {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorInvalidRequest, failureAuthorizationDPoPJKT)
		return
	}
	dpopJKT, dpopError := selectDPoP(client.DPoP.Mode, dpopJKT, false)
	if dpopError != "" {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), dpopError, failureAuthorizationDPoP)
		return
	}
	if q.Get("response_type") != "code" {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorUnsupportedResponseType, failureAuthorizationResponseTypeUnsupported)
		return
	}
	requested := strings.Fields(q.Get("scope"))
	allowed := map[string]bool{"openid": true, "email": true, "profile": true, "groups": true}
	hasOpenID, offline := false, false
	for _, scope := range requested {
		hasOpenID = hasOpenID || scope == "openid"
		offline = offline || scope == "offline_access"
		if !allowed[scope] && scope != "offline_access" {
			s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorInvalidScope, failureAuthorizationScope)
			return
		}
	}
	if !hasOpenID || (offline && (!client.RefreshTokens.Enabled || !client.RefreshTokens.AllowOfflineAccess)) {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorInvalidScope, failureAuthorizationScope)
		return
	}
	if offline && q.Get("prompt") == "none" {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorConsentRequired, failureAuthorizationConsentRequired)
		return
	}
	purpose, noInteraction, validPrompt := authorizationPrompt(q.Get("prompt"))
	if !validPrompt {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorInvalidRequest, failureAuthorizationPrompt)
		return
	}
	if noInteraction {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorLoginRequired, failureAuthorizationLoginRequired)
		return
	}
	sort.Strings(requested)
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		s.redirectAuthorizationError(w, r, redirect, q.Get("state"), oauthAuthorizationErrorInvalidRequest, failureAuthorizationPKCE)
		return
	}
	mode := ""
	if client.RefreshTokens.Enabled {
		mode = "session"
	}
	if offline {
		mode = "offline"
	}
	state := OAuthState{ClientID: clientID, RedirectURI: redirect, CodeChallenge: challenge, Nonce: q.Get("nonce"), OIDCState: q.Get("state"), Scopes: strings.Join(requested, " "), RefreshMode: mode, AuthTime: time.Now(), Purpose: purpose, DPoPJKT: dpopJKT}
	if offline {
		token, err := s.authCodeMgr.EncodeState(state)
		if err != nil {
			s.renderBrowserError(w, http.StatusInternalServerError, failureConsentStateEncode)
			return
		}
		s.renderBrowserPage(w, http.StatusOK, "consent", templates.ConsentData{Title: "Allow offline access", State: token, ClientID: clientID}, failureConsentRender)
		return
	}
	s.continueAuthorization(w, r, state)
}

// selectDPoP validates a canonical thumbprint and applies the configured client mode.
func selectDPoP(mode, thumbprint string, proofPresent bool) (string, oauthAuthorizationError) {
	selected := thumbprint != "" || proofPresent
	if mode == "disabled" && selected {
		return "", oauthAuthorizationErrorInvalidRequest
	}
	if mode == "required" && !selected {
		return "", oauthAuthorizationErrorInvalidRequest
	}
	if thumbprint != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(thumbprint)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != thumbprint {
			return "", oauthAuthorizationErrorInvalidRequest
		}
	}
	if !selected {
		return "", ""
	}
	return thumbprint, ""
}

// handlePushedAuthorize consumes a PAR object and continues with opaque browser state.
func (s *Server) handlePushedAuthorize(w http.ResponseWriter, r *http.Request, clientID, requestURI string) {
	resolved, err := s.policyResolver.ResolveClient(r.Context(), clientID, false)
	if err != nil {
		if errors.Is(err, authpolicy.ErrDenied) {
			s.renderBrowserError(w, http.StatusBadRequest, failureUnknownPushedAuthorizationClient)
		} else {
			s.renderBrowserError(w, http.StatusServiceUnavailable, failurePushedAuthorizationPolicyUnavailable)
		}
		return
	}
	now := time.Now()
	pushed, err := s.store.ConsumePushedRequest(requestURI, clientID, now)
	if err != nil {
		if errors.Is(err, statedb.ErrInvalidGrant) {
			s.renderBrowserError(w, http.StatusBadRequest, failurePushedAuthorization)
		} else {
			s.renderBrowserError(w, http.StatusServiceUnavailable, failurePushedAuthorizationStoreUnavailable)
		}
		return
	}
	client := resolved.Config
	if !s.isValidRedirectURI(pushed.RedirectURI, client) {
		s.renderBrowserError(w, http.StatusBadRequest, failurePushedAuthorizationRedirect)
		return
	}
	if (client.DPoP.Mode == "required") != (pushed.DPoPJKT != "") {
		s.redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, oauthAuthorizationErrorInvalidRequest, failureAuthorizationPARRequest)
		return
	}
	mode := ""
	if client.RefreshTokens.Enabled {
		mode = "session"
	}
	if strings.Contains(" "+pushed.Scopes+" ", " offline_access ") {
		if !client.RefreshTokens.Enabled || !client.RefreshTokens.AllowOfflineAccess {
			s.redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, oauthAuthorizationErrorInvalidRequest, failureAuthorizationPARRequest)
			return
		}
		mode = "offline"
	}
	if strings.Contains(" "+pushed.Scopes+" ", " offline_access ") && pushed.Prompt == "none" {
		s.redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, oauthAuthorizationErrorConsentRequired, failureAuthorizationConsentRequired)
		return
	}
	purpose, noInteraction, validPrompt := authorizationPrompt(pushed.Prompt)
	if !validPrompt {
		s.redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, oauthAuthorizationErrorInvalidRequest, failureAuthorizationPrompt)
		return
	}
	if noInteraction {
		s.redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, oauthAuthorizationErrorLoginRequired, failureAuthorizationLoginRequired)
		return
	}
	state := OAuthState{ClientID: clientID, RedirectURI: pushed.RedirectURI, CodeChallenge: pushed.CodeChallenge, Nonce: pushed.Nonce, OIDCState: pushed.State, Scopes: pushed.Scopes, RefreshMode: mode, AuthTime: now, Purpose: purpose, DPoPJKT: pushed.DPoPJKT, PushedAuthorization: true}
	token, err := s.authCodeMgr.EncodeState(state)
	if err != nil {
		s.renderBrowserError(w, http.StatusInternalServerError, failurePushedAuthorizationStateEncode)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/authorize/continue?"+url.Values{"state": {token}}.Encode(), http.StatusSeeOther)
}

// HandleAuthorizeContinue renders refresh-safe browser interaction after consuming a pushed request.
func (s *Server) HandleAuthorizeContinue(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q) != 1 || len(q["state"]) != 1 || q.Get("state") == "" {
		s.renderBrowserError(w, http.StatusBadRequest, failurePushedAuthorizationContinuation)
		return
	}
	token := q.Get("state")
	state, err := s.authCodeMgr.PeekState(token)
	if err != nil || !state.PushedAuthorization || state.ConnectorID != "" {
		s.renderBrowserError(w, http.StatusBadRequest, failurePushedAuthorizationContinuation)
		return
	}
	if strings.Contains(" "+state.Scopes+" ", " offline_access ") {
		s.renderBrowserPage(w, http.StatusOK, "consent", templates.ConsentData{Title: "Allow offline access", State: token, ClientID: state.ClientID}, failurePushedConsentRender)
		return
	}
	ids := s.connectorIDs()
	if len(ids) == 1 && s.config.UserLoginConnectors[ids[0]].Type != "email" && state.Purpose != "authorize_create" {
		state, err = s.authCodeMgr.DecodeState(token)
		if err != nil {
			s.renderBrowserError(w, http.StatusBadRequest, failurePushedAuthorizationContinuation)
			return
		}
		s.selectConnector(w, r, ids[0], *state)
		return
	}
	s.renderSelectorWithState(w, *state, ids, token)
}

// authorizationPrompt validates supported OIDC prompt profiles and returns durable flow intent.
func authorizationPrompt(prompt string) (purpose string, noInteraction, ok bool) {
	switch prompt {
	case "", "login":
		return "authorize", false, true
	case "create":
		return "authorize_create", false, true
	case "none":
		return "authorize", true, true
	default:
		return "", false, false
	}
}

// HandleConsent accepts or denies explicit offline-access consent.
func (s *Server) HandleConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.renderBrowserError(w, http.StatusMethodNotAllowed, failureConsentMethod)
		return
	}
	if !s.parseBrowserForm(w, r, "state", "decision") {
		return
	}
	state, err := s.authCodeMgr.DecodeState(r.PostForm.Get("state"))
	if err != nil || state.RefreshMode != "offline" {
		s.renderBrowserError(w, http.StatusBadRequest, failureConsentState)
		return
	}
	if r.PostForm.Get("decision") != "accept" {
		s.redirectAuthorizationError(w, r, state.RedirectURI, state.OIDCState, oauthAuthorizationErrorAccessDenied, failureAuthorizationConsentDenied)
		return
	}
	state.OfflineConsent = true
	s.continueAuthorization(w, r, *state)
}

// continueAuthorization begins connector selection after any required consent.
func (s *Server) continueAuthorization(w http.ResponseWriter, r *http.Request, state OAuthState) {
	ids := s.connectorIDs()
	if len(ids) == 1 && s.config.UserLoginConnectors[ids[0]].Type != "email" && state.Purpose != "authorize_create" {
		s.selectConnector(w, r, ids[0], state)
		return
	}
	s.renderSelector(w, state, ids)
}

// redirectAuthorizationError returns an OAuth authorization error to a validated redirect URI.
func (s *Server) redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirect, state string, code oauthAuthorizationError, reason browserFailureReason, attributes ...any) {
	u, err := url.Parse(redirect)
	if err != nil {
		s.renderBrowserError(w, http.StatusBadRequest, failureAuthorizationRedirect)
		return
	}
	status := http.StatusBadRequest
	description := "Sign-in could not be completed. Return to the application and try again."
	switch code {
	case oauthAuthorizationErrorAccessDenied:
		description = "Sign-in was not completed."
	case oauthAuthorizationErrorConsentRequired:
		description = "Sign-in requires your consent."
	case oauthAuthorizationErrorInvalidRequest:
		description = "The sign-in request is invalid or has expired."
	case oauthAuthorizationErrorInvalidScope:
		description = "The application requested unsupported access."
	case oauthAuthorizationErrorLoginRequired:
		description = "Sign-in requires interaction."
	case oauthAuthorizationErrorServer:
		status = http.StatusInternalServerError
		description = "Sign-in is temporarily unavailable. Try again shortly."
	case oauthAuthorizationErrorTemporarilyUnavailable:
		status = http.StatusServiceUnavailable
		description = "Sign-in is temporarily unavailable. Try again shortly."
	case oauthAuthorizationErrorUnsupportedResponseType:
		description = "The application requested an unsupported sign-in response."
	}
	s.logBrowserFailure(status, reason, attributes...)
	query := u.Query()
	query.Set("error", string(code))
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	u.RawQuery = query.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
