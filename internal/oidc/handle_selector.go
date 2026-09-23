// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/truster-dev/truster/v2/internal/templates"
	"golang.org/x/oauth2"
)

// renderSelector renders configured sign-in methods with opaque authorization state.
func (s *Server) renderSelector(w http.ResponseWriter, r *http.Request, state OAuthState, ids []string) {
	token, err := s.authCodeMgr.EncodeState(state)
	if err != nil {
		s.renderBrowserError(w, r, http.StatusInternalServerError, failureSelectorStateEncode)
		return
	}
	s.renderSelectorWithState(w, r, state, ids, token)
}

// renderSelectorWithState renders configured sign-in methods with existing opaque authorization state.
func (s *Server) renderSelectorWithState(w http.ResponseWriter, r *http.Request, state OAuthState, ids []string, token string) {
	items := make([]templates.ConnectorData, 0, len(ids))
	for _, id := range ids {
		cfg := s.config.UserLoginConnectors[id]
		items = append(items, templates.ConnectorData{ID: id, DisplayName: cfg.DisplayName, URL: "/select/" + url.PathEscape(id) + "?state=" + url.QueryEscape(token), Email: cfg.Type == "email"})
	}
	site := ""
	if s.config.Email != nil && s.config.Email.Turnstile != nil {
		site = s.config.Email.Turnstile.SiteKey
	}
	title := "Sign in"
	screen := "login"
	if state.Purpose == "authorize_create" {
		title = "Sign up"
		screen = "signup"
	}
	s.renderBrowserPage(w, r, http.StatusOK, "selector", templates.SelectorData{PageData: s.pageData(r), Title: title, Screen: screen, State: token, SiteKey: site, Connectors: items}, failureSelectorRender)
}

// connectorIDs returns connector IDs in configured display order.
func (s *Server) connectorIDs() []string {
	ids := make([]string, 0, len(s.config.UserLoginConnectors))
	for id := range s.config.UserLoginConnectors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.config.UserLoginConnectors[ids[i]], s.config.UserLoginConnectors[ids[j]]
		if a.Order != b.Order {
			return a.Order < b.Order
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		return ids[i] < ids[j]
	})
	return ids
}

// HandleSelect binds an upstream connector to authorization state.
func (s *Server) HandleSelect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("connector")
	state, err := s.authCodeMgr.DecodeState(r.URL.Query().Get("state"))
	if err != nil {
		s.renderBrowserError(w, r, http.StatusBadRequest, failureSelectorState)
		return
	}
	if state.ConnectorID != "" {
		s.renderBrowserError(w, r, http.StatusBadRequest, failureSelectorStateAlreadyBound)
		return
	}
	s.selectConnector(w, r, id, *state)
}

// selectConnector redirects an authorization flow to an upstream connector.
func (s *Server) selectConnector(w http.ResponseWriter, r *http.Request, id string, state OAuthState) {
	cfg, ok := s.config.UserLoginConnectors[id]
	if !ok {
		s.renderBrowserError(w, r, http.StatusBadRequest, failureConnectorUnknown)
		return
	}
	if cfg.Type == "email" {
		s.renderBrowserError(w, r, http.StatusBadRequest, failureEmailConnectorSelection)
		return
	}
	state.ConnectorID = id
	token, err := s.authCodeMgr.EncodeState(state)
	if err != nil {
		s.renderBrowserError(w, r, http.StatusInternalServerError, failureConnectorStateEncode)
		return
	}
	connector, ok := s.connectors[id]
	if !ok {
		s.renderBrowserError(w, r, http.StatusServiceUnavailable, failureConnectorUnavailable)
		return
	}
	var options []oauth2.AuthCodeOption
	if state.RefreshMode != "" {
		switch cfg.Type {
		case "google":
			options = append(options, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
		case "generic":
			if cfg.Generic != nil && cfg.Generic.Refresh != nil {
				for key, value := range cfg.Generic.Refresh.AuthorizationParams {
					options = append(options, oauth2.SetAuthURLParam(key, value))
				}
				if len(cfg.Generic.Refresh.Scopes) > 0 {
					normalScopes := cfg.Scopes
					if len(normalScopes) == 0 {
						normalScopes = []string{"openid", "email"}
					}
					options = append(options, oauth2.SetAuthURLParam("scope", strings.Join(mergeScopes(normalScopes, cfg.Generic.Refresh.Scopes), " ")))
				}
			}
		}
	}
	http.Redirect(w, r, connector.AuthCodeURL(token, options...), http.StatusFound)
}

// mergeScopes returns stable de-duplicated configured scopes.
func mergeScopes(left, right []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(left)+len(right))
	for _, scope := range append(append([]string(nil), left...), right...) {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	return result
}
