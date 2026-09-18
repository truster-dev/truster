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
	"sync"
	"testing"
	"time"

	"github.com/truster-dev/truster/v2/internal/challenge"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/statedb"
)

// followPushedContinuation follows the refresh-safe redirect after a pushed request is consumed.
func followPushedContinuation(t *testing.T, server *Server, redirect *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	if redirect.Code != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, body=%s", redirect.Code, redirect.Body.String())
	}
	if redirect.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authorize Cache-Control = %q", redirect.Header().Get("Cache-Control"))
	}
	location, err := url.Parse(redirect.Header().Get("Location"))
	if err != nil || location.Path != "/authorize/continue" || location.Query().Get("state") == "" {
		t.Fatalf("authorize location = %q, error=%v", redirect.Header().Get("Location"), err)
	}
	response := httptest.NewRecorder()
	server.HandleAuthorizeContinue(response, httptest.NewRequest(http.MethodGet, location.String(), nil))
	return response
}

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
	authorizeResponse := httptest.NewRecorder()
	server.HandleAuthorize(authorizeResponse, authorize)
	selector := followPushedContinuation(t, server, authorizeResponse)
	match := regexp.MustCompile(`\?state=([^"&]+)`).FindStringSubmatch(selector.Body.String())
	if len(match) != 2 {
		t.Fatalf("selector state not found: %s", selector.Body.String())
	}
	original := match[1]
	continuation, err := url.Parse(authorizeResponse.Header().Get("Location"))
	if err != nil || continuation.Query().Get("state") != original {
		t.Fatalf("selector state differs from continuation: %q", authorizeResponse.Header().Get("Location"))
	}
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
	replayedSelection := httptest.NewRecorder()
	server.HandleSelect(replayedSelection, selectRequest)
	if replayedSelection.Code != http.StatusBadRequest {
		t.Fatalf("replayed selection status = %d", replayedSelection.Code)
	}
	stale := httptest.NewRecorder()
	server.HandleAuthorizeContinue(stale, httptest.NewRequest(http.MethodGet, authorizeResponse.Header().Get("Location"), nil))
	if stale.Code != http.StatusBadRequest {
		t.Fatalf("consumed continuation status = %d", stale.Code)
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
	redirect := httptest.NewRecorder()
	server.HandleAuthorize(redirect, authorize)
	consent := followPushedContinuation(t, server, redirect)
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
	redirect := httptest.NewRecorder()
	server.HandleAuthorize(redirect, front)
	first := followPushedContinuation(t, server, redirect)
	if first.Code != http.StatusOK {
		t.Fatalf("continuation status = %d body=%s", first.Code, first.Body.String())
	}
	location := redirect.Header().Get("Location")
	refreshed := httptest.NewRecorder()
	server.HandleAuthorizeContinue(refreshed, httptest.NewRequest(http.MethodGet, location, nil))
	if refreshed.Code != http.StatusOK || refreshed.Body.String() != first.Body.String() {
		t.Fatalf("refreshed continuation status = %d body=%s", refreshed.Code, refreshed.Body.String())
	}
	second := httptest.NewRecorder()
	server.HandleAuthorize(second, front)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second consume status = %d", second.Code)
	}
}

// TestPushedContinuationPreservesSecurityBindings verifies refresh only peeks at unchanged state.
func TestPushedContinuationPreservesSecurityBindings(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"email": {Type: "email", DisplayName: "Email"}})
	authTime := time.Now().UTC().Truncate(time.Second)
	want := OAuthState{
		ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: "challenge",
		Nonce: "nonce", OIDCState: "downstream-state", Scopes: "email openid", RefreshMode: "session",
		AuthTime: authTime, Purpose: "authorize_create", DPoPJKT: "thumbprint", PushedAuthorization: true,
	}
	token, err := server.authCodeMgr.EncodeState(want)
	if err != nil {
		t.Fatal(err)
	}
	storedBefore, err := server.store.PeekState(token)
	if err != nil {
		t.Fatal(err)
	}
	location := "/authorize/continue?" + url.Values{"state": {token}}.Encode()
	for range 2 {
		response := httptest.NewRecorder()
		server.HandleAuthorizeContinue(response, httptest.NewRequest(http.MethodGet, location, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `name="state" value="`+token+`"`) {
			t.Fatalf("continuation response = %d %s", response.Code, response.Body.String())
		}
	}
	got, err := server.authCodeMgr.PeekState(token)
	if err != nil {
		t.Fatal(err)
	}
	storedAfter, err := server.store.PeekState(token)
	if err != nil {
		t.Fatal(err)
	}
	if !storedAfter.CreatedAt.Equal(storedBefore.CreatedAt) || !storedAfter.ExpiresAt.Equal(storedBefore.ExpiresAt) {
		t.Fatalf("continuation changed state lifetime: before=%v–%v after=%v–%v", storedBefore.CreatedAt, storedBefore.ExpiresAt, storedAfter.CreatedAt, storedAfter.ExpiresAt)
	}
	if got.FlowID != token || got.ClientID != want.ClientID || got.RedirectURI != want.RedirectURI || got.CodeChallenge != want.CodeChallenge || got.Nonce != want.Nonce || got.OIDCState != want.OIDCState || got.Scopes != want.Scopes || got.RefreshMode != want.RefreshMode || !got.AuthTime.Equal(want.AuthTime) || got.OfflineConsent != want.OfflineConsent || got.Purpose != want.Purpose || got.DPoPJKT != want.DPoPJKT || !got.PushedAuthorization {
		t.Fatalf("continuation changed security bindings: %#v", got)
	}
}

// TestPushedContinuationRejectsInvalidTransitions verifies only active unbound PAR state can resume.
func TestPushedContinuationRejectsInvalidTransitions(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"email": {Type: "email", DisplayName: "Email"}})
	nonPAR, err := server.authCodeMgr.EncodeState(OAuthState{ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := server.authCodeMgr.EncodeState(OAuthState{ClientID: "client", ConnectorID: "email", PushedAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := server.authCodeMgr.EncodeState(OAuthState{ClientID: "client", PushedAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.authCodeMgr.DecodeState(consumed); err != nil {
		t.Fatal(err)
	}
	expired, err := statedb.GenerateStateToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = server.store.SaveState(&statedb.OAuthState{StateToken: expired, ClientID: "client", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), PushedAuthorization: true}); err != nil {
		t.Fatal(err)
	}
	valid, err := server.authCodeMgr.EncodeState(OAuthState{ClientID: "client", PushedAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, rawQuery := range []string{"", "state=", "state=" + valid + "&state=" + valid, "state=" + valid + "&extra=two", "state=" + nonPAR, "state=" + bound, "state=" + consumed, "state=" + expired} {
		response := httptest.NewRecorder()
		server.HandleAuthorizeContinue(response, httptest.NewRequest(http.MethodGet, "/authorize/continue?"+rawQuery, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("query %q status = %d", rawQuery, response.Code)
		}
	}
	if _, err = server.authCodeMgr.PeekState(valid); err != nil {
		t.Fatalf("invalid query consumed valid state: %v", err)
	}
}

// TestPushedContinuationActionsAreSingleUse verifies email and consent consume continuation state.
func TestPushedContinuationActionsAreSingleUse(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"email": {Type: "email", DisplayName: "Email"}})
	server.challenge = challenge.Noop{}
	server.mailer = fakeMailer{}
	server.otpSecret = []byte("01234567890123456789012345678901")
	server.config.Email = &config.EmailConfig{OTPTTL: config.Duration(5 * time.Minute)}

	emailState, err := server.authCodeMgr.EncodeState(OAuthState{ClientID: "client", Scopes: "openid", PushedAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	emailLocation := "/authorize/continue?state=" + emailState
	for range 2 {
		preview := httptest.NewRecorder()
		server.HandleAuthorizeContinue(preview, httptest.NewRequest(http.MethodGet, emailLocation, nil))
		if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `name="state" value="`+emailState+`"`) {
			t.Fatalf("email continuation = %d %s", preview.Code, preview.Body.String())
		}
	}
	emailForm := url.Values{"state": {emailState}, "connector": {"email"}, "email": {"user@example.com"}}
	for attempt, wantStatus := range []int{http.StatusOK, http.StatusBadRequest} {
		request := httptest.NewRequest(http.MethodPost, "/email/start", strings.NewReader(emailForm.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		server.HandleEmailStart(response, request)
		if response.Code != wantStatus {
			t.Fatalf("email attempt %d status = %d", attempt+1, response.Code)
		}
	}
	staleEmail := httptest.NewRecorder()
	server.HandleAuthorizeContinue(staleEmail, httptest.NewRequest(http.MethodGet, "/authorize/continue?state="+emailState, nil))
	if staleEmail.Code != http.StatusBadRequest {
		t.Fatalf("consumed email continuation status = %d", staleEmail.Code)
	}

	for _, decision := range []string{"accept", "deny"} {
		t.Run(decision, func(t *testing.T) {
			original := OAuthState{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: "challenge", Nonce: "nonce", OIDCState: "downstream-state", Scopes: "offline_access openid", RefreshMode: "offline", DPoPJKT: "thumbprint", PushedAuthorization: true}
			token, encodeErr := server.authCodeMgr.EncodeState(original)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			var previewBody string
			for range 2 {
				preview := httptest.NewRecorder()
				server.HandleAuthorizeContinue(preview, httptest.NewRequest(http.MethodGet, "/authorize/continue?state="+token, nil))
				if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `name="state" value="`+token+`"`) {
					t.Fatalf("consent continuation = %d %s", preview.Code, preview.Body.String())
				}
				if previewBody != "" && preview.Body.String() != previewBody {
					t.Fatal("consent refresh changed the rendered action")
				}
				previewBody = preview.Body.String()
			}
			previewed, peekErr := server.authCodeMgr.PeekState(token)
			if peekErr != nil || previewed.OfflineConsent {
				t.Fatalf("preview changed consent: state=%#v error=%v", previewed, peekErr)
			}
			form := url.Values{"state": {token}, "decision": {decision}}
			firstStatus := http.StatusOK
			if decision == "deny" {
				firstStatus = http.StatusFound
			}
			request := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			first := httptest.NewRecorder()
			server.HandleConsent(first, request)
			if first.Code != firstStatus {
				t.Fatalf("consent status = %d", first.Code)
			}
			if decision == "accept" {
				match := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(first.Body.String())
				if len(match) != 2 || match[1] == token {
					t.Fatalf("accepted consent replacement missing: %s", first.Body.String())
				}
				replacement, replacementErr := server.authCodeMgr.PeekState(match[1])
				if replacementErr != nil || !replacement.OfflineConsent || replacement.ClientID != original.ClientID || replacement.RedirectURI != original.RedirectURI || replacement.CodeChallenge != original.CodeChallenge || replacement.Nonce != original.Nonce || replacement.OIDCState != original.OIDCState || replacement.Scopes != original.Scopes || replacement.RefreshMode != original.RefreshMode || replacement.DPoPJKT != original.DPoPJKT || !replacement.PushedAuthorization {
					t.Fatalf("accepted consent state=%#v error=%v", replacement, replacementErr)
				}
			} else {
				location, parseErr := url.Parse(first.Header().Get("Location"))
				if parseErr != nil || location.Query().Get("error") != "access_denied" || location.Query().Get("state") != original.OIDCState {
					t.Fatalf("denied consent redirect=%q error=%v", first.Header().Get("Location"), parseErr)
				}
			}
			replayRequest := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
			replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			replay := httptest.NewRecorder()
			server.HandleConsent(replay, replayRequest)
			if replay.Code != http.StatusBadRequest {
				t.Fatalf("replayed consent status = %d", replay.Code)
			}
			stale := httptest.NewRecorder()
			server.HandleAuthorizeContinue(stale, httptest.NewRequest(http.MethodGet, "/authorize/continue?state="+token, nil))
			if stale.Code != http.StatusBadRequest {
				t.Fatalf("consumed consent continuation status = %d", stale.Code)
			}
		})
	}
}

// TestPushedContinuationAutomaticallySelectsProviderOnce verifies concurrent resumes have one winner.
func TestPushedContinuationAutomaticallySelectsProviderOnce(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{"google": {Type: "google", DisplayName: "Google"}})
	token, err := server.authCodeMgr.EncodeState(OAuthState{ClientID: "client", PushedAuthorization: true})
	if err != nil {
		t.Fatal(err)
	}
	location := "/authorize/continue?state=" + token
	responses := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, response := range responses {
		group.Add(1)
		go func(response *httptest.ResponseRecorder) {
			defer group.Done()
			<-start
			server.HandleAuthorizeContinue(response, httptest.NewRequest(http.MethodGet, location, nil))
		}(response)
	}
	close(start)
	group.Wait()
	found, rejected := 0, 0
	for _, response := range responses {
		switch response.Code {
		case http.StatusFound:
			found++
		case http.StatusBadRequest:
			rejected++
		}
	}
	if found != 1 || rejected != 1 {
		t.Fatalf("concurrent continuation statuses = %d, %d", responses[0].Code, responses[1].Code)
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
	redirect := httptest.NewRecorder()
	server.HandleAuthorize(redirect, authorize)
	selector := followPushedContinuation(t, server, redirect)
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
