// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
	"github.com/truster-dev/truster/v2/internal/upstream"
	"golang.org/x/oauth2"
)

// captureConnector records the state passed to its authorization URL.
type captureConnector struct {
	state, authorizationURL string
	identity                upstream.Identity
}

// AuthCodeURL records state and returns a fixed provider URL.
func (c *captureConnector) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	c.state = state
	c.authorizationURL = (&oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/authorize"}}).AuthCodeURL(state, options...)
	return c.authorizationURL
}

// Exchange satisfies upstream.Connector for authorization tests.
func (*captureConnector) Exchange(context.Context, string) (*upstream.Credential, error) {
	return &upstream.Credential{}, nil
}

// Refresh satisfies upstream.Connector for authorization tests.
func (*captureConnector) Refresh(context.Context, *upstream.Credential) (*upstream.Credential, error) {
	return &upstream.Credential{}, nil
}

// GetIdentity returns the configured test identity.
func (c *captureConnector) GetIdentity(context.Context, *oauth2.Token) (upstream.Identity, error) {
	return c.identity, nil
}

// authorizeServer creates a test server and capture connectors.
func authorizeServer(t *testing.T, connectors map[string]config.ConnectorConfig) (*Server, map[string]*captureConnector) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := templates.Load("")
	if err != nil {
		t.Fatal(err)
	}
	registry := make(map[string]upstream.Connector)
	captures := make(map[string]*captureConnector)
	for id, connector := range connectors {
		if connector.Type != "email" {
			capture := &captureConnector{}
			registry[id] = capture
			captures[id] = capture
		}
	}
	requireUserGroupsFromPolicy := false
	cfg := &config.Config{
		UserLoginConnectors: connectors,
		StaticPolicy: config.StaticPolicyConfig{
			RequireUserGroupsFromPolicy: &requireUserGroupsFromPolicy,
			Clients:                     map[string]config.ClientConfig{"client": {RedirectURIs: []string{"https://client.example/callback"}}},
		},
	}
	managerAuth, err := NewAuthCodeManager(store)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(cfg, registry, managerAuth, nil, nil, logger, store, manager, nil, nil, nil, []byte("01234567890123456789012345678901"), nil, nil), captures
}

// authorizationRequest creates a valid downstream authorization request.
func authorizationRequest() *http.Request {
	values := url.Values{
		"client_id":             {"client"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"redirect_uri":          {"https://client.example/callback"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"downstream-state"},
		"nonce":                 {"nonce"},
	}
	return httptest.NewRequest(http.MethodGet, "/authorize?"+values.Encode(), nil)
}

// TestCompleteRedirectsPolicyDrift verifies late policy rejection preserves client state.
func TestCompleteRedirectsPolicyDrift(t *testing.T) {
	server, _ := authorizeServer(t, nil)
	client := server.config.StaticPolicy.Clients["client"]
	client.RequirePAR = true
	server.config.StaticPolicy.Clients["client"] = client
	request := httptest.NewRequest(http.MethodGet, "/callback", nil)
	response := httptest.NewRecorder()
	server.complete(response, request, OAuthState{ClientID: "client", RedirectURI: "https://client.example/callback", OIDCState: "client-state"}, "subject", "user@example.com", true)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Query().Get("error") != "invalid_request" || location.Query().Get("state") != "client-state" {
		t.Fatalf("redirect=%d %q err=%v", response.Code, response.Header().Get("Location"), err)
	}
}

// TestHandleAuthorizeAutomaticallySelectsSingleConnector verifies single-provider bypass.
func TestHandleAuthorizeAutomaticallySelectsSingleConnector(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"google-work": {Type: "google", DisplayName: "Google"},
	})
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, authorizationRequest())
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	state, err := server.authCodeMgr.DecodeState(captures["google-work"].state)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConnectorID != "google-work" || state.RedirectURI != "https://client.example/callback" || state.OIDCState != "downstream-state" {
		t.Fatalf("unexpected state: %#v", state)
	}
}

// TestHandleAuthorizePromptNoneRequiresInteraction verifies Truster never silently authenticates without a browser session.
func TestHandleAuthorizePromptNoneRequiresInteraction(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"email": {Type: "email", DisplayName: "Email"}})
	request := authorizationRequest()
	query := request.URL.Query()
	query.Set("prompt", "none")
	request.URL.RawQuery = query.Encode()
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, request)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Query().Get("error") != "login_required" || location.Query().Get("state") != "downstream-state" {
		t.Fatalf("redirect=%d %q err=%v", response.Code, response.Header().Get("Location"), err)
	}
}

// TestHandleAuthorizeBindsDirectDPoPRequest verifies required direct requests preserve a canonical thumbprint.
func TestHandleAuthorizeBindsDirectDPoPRequest(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"google-work": {Type: "google", DisplayName: "Google"},
	})
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	thumbprintBytes := sha256.Sum256([]byte("public key"))
	thumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes[:])
	request := authorizationRequest()
	query := request.URL.Query()
	query.Set("dpop_jkt", thumbprint)
	request.URL.RawQuery = query.Encode()

	response := httptest.NewRecorder()
	server.HandleAuthorize(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusFound, response.Body.String())
	}
	state, err := server.authCodeMgr.DecodeState(captures["google-work"].state)
	if err != nil {
		t.Fatal(err)
	}
	if state.DPoPJKT != thumbprint {
		t.Fatalf("DPoP binding = %q", state.DPoPJKT)
	}
}

// TestHandleAuthorizeRedirectsDuplicateDPoPThumbprint verifies safe authorization errors preserve state.
func TestHandleAuthorizeRedirectsDuplicateDPoPThumbprint(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{
		"google-work": {Type: "google", DisplayName: "Google"},
	})
	request := authorizationRequest()
	query := request.URL.Query()
	query["dpop_jkt"] = []string{"one", "two"}
	request.URL.RawQuery = query.Encode()
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want redirect: %s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("error") != "invalid_request" || location.Query().Get("error_description") == "" || location.Query().Get("state") != "downstream-state" {
		t.Fatalf("redirect query = %v", location.Query())
	}
}

// TestHandleAuthorizeRejectsInvalidDirectDPoPInputs verifies empty bindings and proof headers fail after redirect validation.
func TestHandleAuthorizeRejectsInvalidDirectDPoPInputs(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{
		"google-work": {Type: "google", DisplayName: "Google"},
	})
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.URL.RawQuery += "&dpop_jkt=" },
		func(request *http.Request) { request.Header.Set("DPoP", "proof") },
	} {
		request := authorizationRequest()
		mutate(request)
		response := httptest.NewRecorder()
		server.HandleAuthorize(response, request)
		if response.Code != http.StatusFound {
			t.Fatalf("status = %d, want redirect: %s", response.Code, response.Body.String())
		}
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil || location.Query().Get("error") != "invalid_request" || location.Query().Get("state") != "downstream-state" {
			t.Fatalf("location = %q, error = %v", response.Header().Get("Location"), err)
		}
	}
}

// TestHandleAuthorizeRejectsEmptyPushedRequest verifies PAR syntax cannot fall through to direct authorization.
func TestHandleAuthorizeRejectsEmptyPushedRequest(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"google-work": {Type: "google", DisplayName: "Google"}})
	request := authorizationRequest()
	request.URL.RawQuery += "&request_uri="
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(response.Body.String(), "Unable to continue") {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

// TestCallbackCompletionRechecksRemovedClient verifies policy removal prevents code issuance.
func TestCallbackCompletionRechecksRemovedClient(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"google": {Type: "google", DisplayName: "Google"},
	})
	client := server.config.StaticPolicy.Clients["client"]
	resolver := &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: client}, clientErrors: []error{nil, authpolicy.ErrDenied}}
	server.policyResolver = resolver
	captures["google"].identity = upstream.Identity{Subject: "upstream-user", Emails: []upstream.Email{{Address: "user@example.com", Verified: true}}}

	authorize := httptest.NewRecorder()
	server.HandleAuthorize(authorize, authorizationRequest())
	if authorize.Code != http.StatusFound {
		t.Fatalf("authorize status = %d: %s", authorize.Code, authorize.Body.String())
	}
	callback := httptest.NewRecorder()
	callbackURL := "/callback/google?code=upstream-code&state=" + url.QueryEscape(captures["google"].state)
	server.HandleCallback(callback, httptest.NewRequest(http.MethodGet, callbackURL, nil))
	if callback.Code != http.StatusForbidden || resolver.resolveClientCalls != 2 || resolver.resolveUserCalls != 0 {
		t.Fatalf("callback status=%d client_calls=%d user_calls=%d body=%s", callback.Code, resolver.resolveClientCalls, resolver.resolveUserCalls, callback.Body.String())
	}
}

// TestHandleAuthorizeUsesResolvedClientPolicy verifies dynamic redirects and resolver failure mapping.
func TestHandleAuthorizeUsesResolvedClientPolicy(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"google": {Type: "google"}})
	dynamic := config.ClientConfig{RedirectURIs: []string{"https://dynamic.example/callback"}}
	tests := []struct {
		name, redirect string
		err            error
		want           int
	}{
		{name: "exact dynamic redirect", redirect: dynamic.RedirectURIs[0], want: http.StatusFound},
		{name: "wrong dynamic redirect", redirect: "https://client.example/callback", want: http.StatusBadRequest},
		{name: "unknown client", redirect: dynamic.RedirectURIs[0], err: authpolicy.ErrDenied, want: http.StatusBadRequest},
		{name: "indeterminate", redirect: dynamic.RedirectURIs[0], err: &authpolicy.IndeterminateError{Err: context.DeadlineExceeded}, want: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: dynamic}, clientErrors: []error{test.err}}
			server.policyResolver = fake
			request := authorizationRequest()
			query := request.URL.Query()
			query.Set("client_id", "dynamic")
			query.Set("redirect_uri", test.redirect)
			request.URL.RawQuery = query.Encode()
			response := httptest.NewRecorder()
			server.HandleAuthorize(response, request)
			if response.Code != test.want || fake.resolveClientCalls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, fake.resolveClientCalls, response.Body.String())
			}
		})
	}
	if server.isValidRedirectURI("https://client.example/callback", config.ClientConfig{}) {
		t.Fatal("client without redirect policy inherited static defaults")
	}
}
