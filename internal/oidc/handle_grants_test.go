// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
)

// grantsServer creates a grant-management handler with real storage and templates.
func grantsServer(t *testing.T) (*Server, *statedb.Store) {
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
	return &Server{store: store, templates: manager, logger: logger}, store
}

// TestHandleGrantsStartsDedicatedAuthentication verifies grant management cannot reuse an authorization flow.
func TestHandleGrantsStartsDedicatedAuthentication(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"provider": {Type: "google", DisplayName: "Provider"},
	})
	response := httptest.NewRecorder()
	server.HandleGrants(response, httptest.NewRequest(http.MethodGet, "/grants", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	state, err := server.authCodeMgr.DecodeState(captures["provider"].state)
	if err != nil {
		t.Fatal(err)
	}
	if state.Purpose != "manage_grants" || state.ClientID != "" || state.RedirectURI != "" {
		t.Fatalf("unexpected grant-management state: %#v", state)
	}

	methodResponse := httptest.NewRecorder()
	server.HandleGrants(methodResponse, httptest.NewRequest(http.MethodPost, "/grants", nil))
	if methodResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want %d", methodResponse.Code, http.StatusMethodNotAllowed)
	}
}

// TestRenderGrantsCreatesUsableSingleUseAction verifies rendering and atomic self-service revocation.
func TestRenderGrantsCreatesUsableSingleUseAction(t *testing.T) {
	server, store := grantsServer(t)
	material := createRevocableGrant(t, store, "managed-sid", "managed-client")
	response := httptest.NewRecorder()
	server.renderGrants(response, httptest.NewRequest(http.MethodGet, "/grants", nil), "USER@example.com")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("render response = %d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "managed-client") || !strings.Contains(body, `action="/grants/revoke"`) || strings.Contains(body, "/grants/revoke?") || strings.Contains(body, material.Token) {
		t.Fatalf("unsafe or incomplete grants page: %s", body)
	}
	match := regexp.MustCompile(`name="action_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 || match[1] == "" {
		t.Fatalf("action token missing from grants page: %s", body)
	}
	values := url.Values{"action_token": {match[1]}, "email": {"user@example.com"}, "sid": {"managed-sid"}}
	request := httptest.NewRequest(http.MethodPost, "/grants/revoke", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeResponse := httptest.NewRecorder()
	server.HandleGrantRevoke(revokeResponse, request)
	if revokeResponse.Code != http.StatusOK || !strings.Contains(revokeResponse.Body.String(), "grant was revoked") {
		t.Fatalf("revoke response = %d %q", revokeResponse.Code, revokeResponse.Body.String())
	}
	if _, _, err := store.PrepareRefresh(material, "managed-client", time.Now()); err != statedb.ErrInvalidGrant {
		t.Fatalf("managed grant after revocation = %v, want ErrInvalidGrant", err)
	}

	replayResponse := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodPost, "/grants/revoke", strings.NewReader(values.Encode()))
	replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.HandleGrantRevoke(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusBadRequest || !strings.Contains(replayResponse.Body.String(), "invalid, expired, or already used") {
		t.Fatalf("replay response = %d %q", replayResponse.Code, replayResponse.Body.String())
	}
}

// TestHandleGrantRevokeRejectsInvalidInput verifies actions remain bound to a valid normalized identity.
func TestHandleGrantRevokeRejectsInvalidInput(t *testing.T) {
	server, _ := grantsServer(t)
	tests := []struct {
		name, method, body string
		wantStatus         int
	}{
		{name: "wrong method", method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		{name: "invalid email", method: http.MethodPost, body: "action_token=x&email=not-an-email&sid=sid", wantStatus: http.StatusBadRequest},
		{name: "unknown action", method: http.MethodPost, body: "action_token=x&email=user%40example.com&sid=sid", wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/grants/revoke", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			server.HandleGrantRevoke(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}
