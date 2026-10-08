// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/truster-dev/truster/v3/internal/config"
)

// TestConnectorSelectorPreservesOpaqueAuthorizationRequest verifies selection cannot modify authorization state.
func TestConnectorSelectorPreservesOpaqueAuthorizationRequest(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"google": {Type: "google", DisplayName: "Google", Order: 10},
		"github": {Type: "github", DisplayName: "GitHub", Order: 20},
	})
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, authorizationRequest())
	if response.Code != http.StatusOK || !regexp.MustCompile(`<h1>Sign in</h1>`).Match(response.Body.Bytes()) {
		t.Fatalf("unexpected selector response: %d %s", response.Code, response.Body.String())
	}
	match := regexp.MustCompile(`href="([^"]*select/google[^"]*)"`).FindStringSubmatch(response.Body.String())
	if len(match) != 2 {
		t.Fatalf("Google selection URL not found: %s", response.Body.String())
	}
	selectionURL := html.UnescapeString(match[1]) + "&redirect_uri=https%3A%2F%2Fevil.example"
	request := httptest.NewRequest(http.MethodGet, selectionURL, nil)
	selected := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /select/{connector}", server.HandleSelect)
	mux.ServeHTTP(selected, request)
	if selected.Code != http.StatusFound {
		t.Fatalf("selection status = %d: %s", selected.Code, selected.Body.String())
	}
	state, err := server.authCodeMgr.DecodeState(captures["google"].state)
	if err != nil {
		t.Fatal(err)
	}
	if state.RedirectURI != "https://client.example/callback" || state.ConnectorID != "google" || state.CodeChallenge != "challenge" {
		t.Fatalf("selection state was modified: %#v", state)
	}
	replay := httptest.NewRecorder()
	mux.ServeHTTP(replay, request)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("selection replay status = %d, want %d", replay.Code, http.StatusBadRequest)
	}
}

// TestConnectorSelectorRendersSingleEmailConnectorInline verifies email remains an inline form.
func TestConnectorSelectorRendersSingleEmailConnectorInline(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{
		"email": {Type: "email", DisplayName: "Email"},
	})
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, authorizationRequest())
	if response.Code != http.StatusOK || !regexp.MustCompile(`action="/email/start"`).Match(response.Body.Bytes()) || !regexp.MustCompile(`name="connector"\s+value="email"`).Match(response.Body.Bytes()) {
		t.Fatalf("unexpected email response: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "/select/email") {
		t.Fatalf("email rendered as a separate selection link: %s", response.Body.String())
	}
}

// TestConnectorSelectorRendersEmailAndTurnstile verifies combined selector rendering.
func TestConnectorSelectorRendersEmailAndTurnstile(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{
		"google": {Type: "google", DisplayName: "Google"},
		"email":  {Type: "email", DisplayName: "Email"},
	})
	server.config.Email = &config.EmailConfig{Turnstile: &config.TurnstileConfig{SiteKey: "turnstile-site-key"}}
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, authorizationRequest())
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "/select/google") || !strings.Contains(body, `action="/email/start"`) || !strings.Contains(body, `data-sitekey="turnstile-site-key"`) {
		t.Fatalf("unexpected combined selector response: %d %s", response.Code, body)
	}
}

// TestGenericRefreshScopesIncludeConnectorDefaults verifies renewable scopes augment normal defaults.
func TestGenericRefreshScopesIncludeConnectorDefaults(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"generic": {Type: "generic", DisplayName: "Generic", Generic: &config.GenericConfig{Refresh: &config.GenericRefreshConfig{Scopes: []string{"offline_access"}}}},
	})
	response := httptest.NewRecorder()
	server.selectConnector(response, httptest.NewRequest(http.MethodGet, "/", nil), "generic", OAuthState{RefreshMode: "session"})
	if response.Code != http.StatusFound {
		t.Fatalf("selection status = %d", response.Code)
	}
	u, err := url.Parse(captures["generic"].authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("scope"); got != "openid email offline_access" {
		t.Fatalf("scope = %q", got)
	}
}
