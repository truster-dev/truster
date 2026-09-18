// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/truster-dev/truster/v2/internal/config"
)

// TestPushedAuthorizeReplacesConsumedState verifies connector selection replaces browser state.
func TestPushedAuthorizeReplacesConsumedState(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"one": {Type: "google", DisplayName: "One"}, "two": {Type: "generic", DisplayName: "Two"}})
	values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
	par := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
	par.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parResponse := httptest.NewRecorder()
	server.HandlePAR(parResponse, par)
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(parResponse.Body.Bytes(), &pushed); err != nil {
		t.Fatal(err)
	}
	authorize := httptest.NewRequest(http.MethodGet, "/authorize?client_id=client&request_uri="+url.QueryEscape(pushed.RequestURI), nil)
	selector := httptest.NewRecorder()
	server.HandleAuthorize(selector, authorize)
	match := regexp.MustCompile(`\?state=([^"&]+)`).FindStringSubmatch(selector.Body.String())
	if len(match) != 2 {
		t.Fatalf("selector state not found: %s", selector.Body.String())
	}
	original := match[1]
	peeked, err := server.authCodeMgr.PeekState(original)
	if err != nil || peeked.FlowID != original || peeked.ConnectorID != "" {
		t.Fatalf("original PAR state peek=%#v err=%v", peeked, err)
	}
	selectRequest := httptest.NewRequest(http.MethodGet, "/select/one?state="+url.QueryEscape(original), nil)
	selectRequest.SetPathValue("connector", "one")
	selected := httptest.NewRecorder()
	server.HandleSelect(selected, selectRequest)
	if _, err = server.authCodeMgr.PeekState(original); err == nil {
		t.Fatal("original PAR state remained after connector selection")
	}
	redirect, err := url.Parse(selected.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	replacement := redirect.Query().Get("state")
	peeked, err = server.authCodeMgr.PeekState(replacement)
	if err != nil || peeked.ConnectorID != "one" || replacement == original {
		t.Fatalf("replacement state=%q peek=%#v err=%v", replacement, peeked, err)
	}
}

// TestPushedAuthorizeConsentPersistsBrowserState verifies offline consent receives durable browser state.
func TestPushedAuthorizeConsentPersistsBrowserState(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"email": {Type: "email", DisplayName: "Email"}})
	client := server.config.StaticPolicy.Clients["client"]
	client.RefreshTokens.Enabled, client.RefreshTokens.AllowOfflineAccess = true, true
	server.config.StaticPolicy.Clients["client"] = client
	values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid offline_access"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
	par := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
	par.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parResponse := httptest.NewRecorder()
	server.HandlePAR(parResponse, par)
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(parResponse.Body.Bytes(), &pushed); err != nil {
		t.Fatal(err)
	}
	authorize := httptest.NewRequest(http.MethodGet, "/authorize?client_id=client&request_uri="+url.QueryEscape(pushed.RequestURI), nil)
	consent := httptest.NewRecorder()
	server.HandleAuthorize(consent, authorize)
	match := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(consent.Body.String())
	if len(match) != 2 {
		t.Fatalf("consent state not found: %s", consent.Body.String())
	}
	peeked, err := server.authCodeMgr.PeekState(match[1])
	if err != nil || peeked.FlowID != match[1] || peeked.Scopes != "offline_access openid" {
		t.Fatalf("consent PAR state peek=%#v err=%v", peeked, err)
	}
}

// TestHandlePARStoresOneTimeRequest verifies the basic RFC 9126 round trip and single use.
func TestHandlePARStoresOneTimeRequest(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"email": {Type: "email", DisplayName: "Email"}})
	server.config.IssuerURL = "https://issuer.example/prefix/"
	values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
	request := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandlePAR(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	var result struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewRequest(http.MethodGet, "/authorize?client_id=client&request_uri="+url.QueryEscape(result.RequestURI), nil)
	first := httptest.NewRecorder()
	server.HandleAuthorize(first, front)
	if first.Code != http.StatusOK {
		t.Fatalf("first consume status = %d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	server.HandleAuthorize(second, front)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second consume status = %d", second.Code)
	}
}

// TestHandlePARRejectsDuplicateParameters verifies strict form parsing.
func TestHandlePARRejectsDuplicateParameters(t *testing.T) {
	server, _ := authorizeServer(t, nil)
	request := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader("client_id=client&client_id=client"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandlePAR(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}

// TestHandlePARPromptCreateRendersSignup verifies the standardized create intent reaches browser presentation.
func TestHandlePARPromptCreateRendersSignup(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"google": {Type: "google", DisplayName: "Google"}})
	values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "prompt": {"create"}}
	request := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandlePAR(response, request)
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &pushed) != nil {
		t.Fatalf("PAR response=%d %q", response.Code, response.Body.String())
	}
	authorize := httptest.NewRequest(http.MethodGet, "/authorize?client_id=client&request_uri="+url.QueryEscape(pushed.RequestURI), nil)
	selector := httptest.NewRecorder()
	server.HandleAuthorize(selector, authorize)
	if selector.Code != http.StatusOK || !strings.Contains(selector.Body.String(), "<h1>Sign up</h1>") {
		t.Fatalf("selector response=%d %q", selector.Code, selector.Body.String())
	}
}

// TestHandlePARRejectsUnsupportedPrompt verifies unknown and combined prompt profiles fail at PAR.
func TestHandlePARRejectsUnsupportedPrompt(t *testing.T) {
	for _, prompt := range []string{"signup", "create login"} {
		t.Run(prompt, func(t *testing.T) {
			server, _ := authorizeServer(t, nil)
			values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "prompt": {prompt}}
			request := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			server.HandlePAR(response, request)
			if response.Code != http.StatusBadRequest || response.Body.String() != "{\"error\":\"invalid_request\"}\n" {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
		})
	}
}

// TestHandlePARRejectsUnsupportedInputs verifies the bounded public-client request boundary.
func TestHandlePARRejectsUnsupportedInputs(t *testing.T) {
	valid := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
	for _, test := range []struct {
		name, body, authorization string
		want                      int
	}{
		{name: "request URI", body: valid.Encode() + "&request_uri=urn%3Aexample", want: http.StatusBadRequest},
		{name: "client secret", body: valid.Encode() + "&client_secret=secret", want: http.StatusBadRequest},
		{name: "authorization header", body: valid.Encode(), authorization: "Basic Y2xpZW50OnNlY3JldA==", want: http.StatusBadRequest},
		{name: "oversized body", body: "padding=" + strings.Repeat("x", maxPARBody), want: http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := authorizeServer(t, nil)
			request := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response := httptest.NewRecorder()
			server.HandlePAR(response, request)
			if response.Code != test.want || !strings.Contains(response.Body.String(), "invalid_request") {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
		})
	}
}

// TestPushedAuthorizeRedirectsPolicyDrift verifies errors preserve state after redirect validation.
func TestPushedAuthorizeRedirectsPolicyDrift(t *testing.T) {
	for _, test := range []struct {
		name, scope string
		configure   func(*config.ClientConfig)
		change      func(*config.ClientConfig)
	}{
		{
			name: "DPoP becomes required", scope: "openid",
			change: func(client *config.ClientConfig) {
				client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
			},
		},
		{
			name: "offline access disabled", scope: "openid offline_access",
			configure: func(client *config.ClientConfig) {
				client.RefreshTokens.Enabled, client.RefreshTokens.AllowOfflineAccess = true, true
			},
			change: func(client *config.ClientConfig) { client.RefreshTokens.AllowOfflineAccess = false },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := authorizeServer(t, nil)
			client := server.config.StaticPolicy.Clients["client"]
			if test.configure != nil {
				test.configure(&client)
			}
			server.config.StaticPolicy.Clients["client"] = client
			values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {test.scope}, "state": {"client-state"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
			request := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			server.HandlePAR(response, request)
			var pushed struct {
				RequestURI string `json:"request_uri"`
			}
			if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &pushed) != nil {
				t.Fatalf("PAR response=%d %q", response.Code, response.Body.String())
			}
			client = server.config.StaticPolicy.Clients["client"]
			test.change(&client)
			server.config.StaticPolicy.Clients["client"] = client
			authorize := httptest.NewRequest(http.MethodGet, "/authorize?client_id=client&request_uri="+url.QueryEscape(pushed.RequestURI), nil)
			redirect := httptest.NewRecorder()
			server.HandleAuthorize(redirect, authorize)
			location, err := url.Parse(redirect.Header().Get("Location"))
			if err != nil || redirect.Code != http.StatusFound || location.Query().Get("error") != "invalid_request" || location.Query().Get("state") != "client-state" {
				t.Fatalf("redirect=%d %q err=%v", redirect.Code, redirect.Header().Get("Location"), err)
			}
		})
	}
}

// TestHandlePARAcceptsDPoPProfilesAndRejectsReplay verifies both configured PAR profiles.
func TestHandlePARAcceptsDPoPProfilesAndRejectsReplay(t *testing.T) {
	for _, algorithm := range []string{"ES256", "ES512"} {
		t.Run(algorithm, func(t *testing.T) {
			server, _ := authorizeServer(t, nil)
			server.config.IssuerURL = "https://issuer.example"
			client := server.config.StaticPolicy.Clients["client"]
			client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: algorithm}
			server.config.StaticPolicy.Clients["client"] = client
			key := newEndpointProofKey(t, algorithm)
			proof := key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/par", IAT: time.Now(), JTI: "par-" + algorithm})
			request := func(jkt string) *httptest.ResponseRecorder {
				values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
				if jkt != "" {
					values.Set("dpop_jkt", jkt)
				}
				r := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("DPoP", proof)
				w := httptest.NewRecorder()
				server.HandlePAR(w, r)
				return w
			}
			otherAlgorithm := "ES512"
			if algorithm == "ES512" {
				otherAlgorithm = "ES256"
			}
			wrongAlgorithm := newEndpointProofKey(t, otherAlgorithm).proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/par", IAT: time.Now(), JTI: "wrong-algorithm"})
			original := proof
			proof = wrongAlgorithm
			if response := request(""); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_dpop_proof") {
				t.Fatalf("wrong algorithm status=%d body=%s", response.Code, response.Body.String())
			}
			proof = original
			if response := request(""); response.Code != http.StatusCreated {
				t.Fatalf("proof-only status=%d body=%s", response.Code, response.Body.String())
			}
			if response := request(""); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_dpop_proof") {
				t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

// TestHandlePARValidatesExplicitDPoPThumbprint verifies proof and dpop_jkt must identify one key.
func TestHandlePARValidatesExplicitDPoPThumbprint(t *testing.T) {
	server, _ := authorizeServer(t, nil)
	server.config.IssuerURL = "https://issuer.example"
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	key, wrong := newEndpointProofKey(t, "ES256"), newEndpointProofKey(t, "ES256")
	for _, test := range []struct {
		name, jkt, jti string
		want           int
	}{{"matching", key.jkt, "matching", http.StatusCreated}, {"mismatch", wrong.jkt, "mismatch", http.StatusBadRequest}} {
		t.Run(test.name, func(t *testing.T) {
			values := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "dpop_jkt": {test.jkt}}
			request := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("DPoP", key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/par", IAT: time.Now(), JTI: test.jti}))
			response := httptest.NewRecorder()
			server.HandlePAR(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
