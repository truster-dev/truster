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
	"github.com/truster-dev/truster/v3/internal/upstream"
)

// TestIdentitySelectionRejectsTamperingAndReplay verifies exact, single-use email selection.
func TestIdentitySelectionRejectsTamperingAndReplay(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"github": {Type: "github", DisplayName: "GitHub"},
	})
	captures["github"].identity = upstream.Identity{Subject: "123", Emails: []upstream.Email{
		{Address: "primary@example.com", Primary: true},
		{Address: "verified@example.com", Verified: true},
	}}
	authorize := httptest.NewRecorder()
	server.HandleAuthorize(authorize, authorizationRequest())
	callbackURL := "/callback/github?code=upstream-code&state=" + url.QueryEscape(captures["github"].state)
	callback := httptest.NewRecorder()
	server.HandleCallback(callback, httptest.NewRequest(http.MethodGet, callbackURL, nil))
	match := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(callback.Body.String())
	if callback.Code != http.StatusOK || len(match) != 2 || !strings.Contains(callback.Body.String(), "Unverified") || !strings.Contains(callback.Body.String(), "Verified") {
		t.Fatalf("unexpected selection page: %d %s", callback.Code, callback.Body.String())
	}
	token := html.UnescapeString(match[1])
	tamperedPrefix := "A"
	if token[0] == 'A' {
		tamperedPrefix = "B"
	}
	tampered := tamperedPrefix + token[1:]
	tamperedResponse := httptest.NewRecorder()
	server.HandleIdentitySelect(tamperedResponse, identitySelectionRequest(tampered, "1"))
	if tamperedResponse.Code != http.StatusBadRequest {
		t.Fatalf("tampered token status = %d, want %d", tamperedResponse.Code, http.StatusBadRequest)
	}

	selected := httptest.NewRecorder()
	server.HandleIdentitySelect(selected, identitySelectionRequest(token, "0"))
	if selected.Code != http.StatusFound {
		t.Fatalf("selection status = %d: %s", selected.Code, selected.Body.String())
	}
	redirect, err := url.Parse(selected.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := server.authCodeMgr.ValidateAndExtract(redirect.Query().Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	if payload.Email != "primary@example.com" {
		t.Fatalf("selected email = %q", payload.Email)
	}
	if payload.EmailVerified {
		t.Fatal("selected unverified email was marked verified")
	}

	replay := httptest.NewRecorder()
	server.HandleIdentitySelect(replay, identitySelectionRequest(token, "0"))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want %d", replay.Code, http.StatusBadRequest)
	}
}

// identitySelectionRequest creates a selection form request.
func identitySelectionRequest(token, index string) *http.Request {
	form := url.Values{"token": {token}, "index": {index}}
	request := httptest.NewRequest(http.MethodPost, "/identity/select", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}
