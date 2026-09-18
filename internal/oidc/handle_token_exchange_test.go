// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/tokens"
	"github.com/truster-dev/truster/v2/internal/trust"
)

const (
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	idTokenType        = "urn:ietf:params:oauth:token-type:id_token"
)

// tokenExchangeIssuer is a local TLS discovery, JWKS, and signing fixture.
type tokenExchangeIssuer struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

// newTokenExchangeIssuer starts a local TLS OIDC issuer.
func newTokenExchangeIssuer(t *testing.T) *tokenExchangeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &tokenExchangeIssuer{t: t, key: key, kid: "upstream-key"}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	return fixture
}

// serveHTTP serves the fixture's discovery document and public key.
func (f *tokenExchangeIssuer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL, "jwks_uri": f.server.URL + "/jwks"})
	case "/jwks":
		key, err := jwk.FromRaw(&f.key.PublicKey)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = key.Set(jwk.KeyIDKey, f.kid)
		_ = key.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk.Key{key}})
	default:
		http.NotFound(w, r)
	}
}

// sign creates an upstream ID token with optional claim replacements.
func (f *tokenExchangeIssuer) sign(replacements map[string]any) string {
	f.t.Helper()
	now := time.Now().UTC()
	claims := map[string]any{"iss": f.server.URL, "sub": "upstream-user", "aud": "client", "iat": now, "exp": now.Add(10 * time.Minute), "repository": "acme/project"}
	for name, value := range replacements {
		claims[name] = value
	}
	token := jwt.New()
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			f.t.Fatal(err)
		}
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, f.kid)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, f.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(signed)
}

// tokenExchangeServer constructs NewServer with compiled trust configuration and a real signer.
func tokenExchangeServer(t *testing.T, issuer *tokenExchangeIssuer, policies int) (*Server, *tokens.SigningKey) {
	t.Helper()
	policyConfig := make(map[string]config.TrustPolicyConfig, policies)
	bindings := make([]config.TrustBindingConfig, policies)
	for i := 0; i < policies; i++ {
		name := "policy-" + string(rune('a'+i))
		policyConfig[name] = config.TrustPolicyConfig{Issuer: "local", Subject: "trusted:builder", Groups: []string{"builders", "release"}, Claims: map[string]json.RawMessage{"repository": json.RawMessage(`{"const":"acme/project"}`)}}
		bindings[i] = config.TrustBindingConfig{ID: "binding-" + name, TrustPolicy: name}
	}
	cfg := &config.Config{
		IssuerURL:           "https://downstream.example",
		HTTPListenAddr:      ":8080",
		Secrets:             config.SecretsConfig{Provider: "env", SigningKeyName: "KEY"},
		UserLoginConnectors: map[string]config.ConnectorConfig{"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "GOOGLE_KEY"}},
		ServiceTokenIssuers: map[string]config.TrustIssuerConfig{"local": {Provider: "oidc", IssuerURL: issuer.server.URL, SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}},
		IDTokenTTL:          config.Duration(20 * time.Minute),
		AccessTokenTTL:      config.Duration(time.Hour),
		StaticPolicy: config.StaticPolicyConfig{
			DefaultRedirectURIs: []string{"http://localhost/callback"},
			UserGroupMappings:   map[string]map[string][]string{},
			TrustPolicies:       policyConfig,
			Clients:             map[string]config.ClientConfig{"client": {TrustBindings: bindings}, "other-client": {}},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.jsonc"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	key := newTestSigningKey(t)
	signer := tokens.NewSigner(key, "downstream-key", loaded.IssuerURL, time.Hour)
	originalTransport := http.DefaultTransport
	http.DefaultTransport = issuer.server.Client().Transport
	server := NewServer(loaded, nil, nil, signer, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	http.DefaultTransport = originalTransport
	return server, key
}

// tokenExchangeRequest submits form values to the production token handler.
func tokenExchangeRequest(server *Server, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleToken(response, request)
	return response
}

// validTokenExchangeForm returns a complete RFC 8693 ID-token exchange form.
func validTokenExchangeForm(raw string) url.Values {
	return url.Values{"grant_type": {tokenExchangeGrant}, "client_id": {"client"}, "subject_token": {raw}, "subject_token_type": {idTokenType}, "requested_token_type": {idTokenType}}
}

// TestTokenExchangeRejectsDPoPAtBoundary verifies RFC 8693 does not accept a supplied proof.
func TestTokenExchangeRejectsDPoPAtBoundary(t *testing.T) {
	server := &Server{}
	values := validTokenExchangeForm("subject")
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", "supplied")
	response := httptest.NewRecorder()
	server.HandleToken(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestTokenExchangePolicyResolver verifies live trust replacement, exact matching, and temporary failures.
func TestTokenExchangePolicyResolver(t *testing.T) {
	issuer := newTokenExchangeIssuer(t)
	server, signingKey := tokenExchangeServer(t, issuer, 2)
	staticClient := server.config.StaticPolicy.Clients["client"]
	first := staticClient.TrustBindings[0].Effective
	second := staticClient.TrustBindings[1].Effective
	firstDynamic := config.EffectiveTrustBinding{ID: "live-first", Subject: "current:first", Groups: []string{"current-a"}, Schema: first.Schema}
	secondDynamic := config.EffectiveTrustBinding{ID: "live-second", Subject: "current:second", Groups: []string{"current-b"}, Schema: second.Schema}
	fake := &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: staticClient}, trust: []config.EffectiveTrustBinding{firstDynamic}}
	server.policyResolver = fake
	originalTransport := http.DefaultTransport
	http.DefaultTransport = issuer.server.Client().Transport
	server.trust = trust.NewService(server.config, fake)
	http.DefaultTransport = originalTransport
	assertIdentity := func(subject, group string) {
		t.Helper()
		response := tokenExchangeRequest(server, validTokenExchangeForm(issuer.sign(nil)))
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var body struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		verified, err := jwt.Parse([]byte(body.AccessToken), jwt.WithKey(signingKey.Algorithm, signingKey.PublicKey), jwt.WithValidate(true))
		if err != nil {
			t.Fatal(err)
		}
		groups, _ := verified.Get("groups")
		encoded, _ := json.Marshal(groups)
		if verified.Subject() != subject || string(encoded) != `["`+group+`"]` {
			t.Fatalf("subject=%q groups=%s", verified.Subject(), encoded)
		}
	}
	assertIdentity("current:first", "current-a")
	fake.trust = []config.EffectiveTrustBinding{secondDynamic}
	assertIdentity("current:second", "current-b")
	for name, bindings := range map[string][]config.EffectiveTrustBinding{"zero": {}, "ambiguous": {firstDynamic, secondDynamic}} {
		t.Run(name, func(t *testing.T) {
			fake.trust = bindings
			response := tokenExchangeRequest(server, validTokenExchangeForm(issuer.sign(nil)))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	fake.trustErr = &authpolicy.IndeterminateError{Err: context.DeadlineExceeded}
	var logs bytes.Buffer
	server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	response := tokenExchangeRequest(server, validTokenExchangeForm(issuer.sign(nil)))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("indeterminate status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(logs.String(), `"client_id":"client"`) || !strings.Contains(logs.String(), `"result":"indeterminate"`) || strings.Contains(logs.String(), `"result":"denied"`) {
		t.Fatalf("indeterminate exchange log=%s", logs.String())
	}
	fake.trustErr = nil
	fake.trust = []config.EffectiveTrustBinding{firstDynamic}
	assertIdentity("current:first", "current-a")
}

// TestTokenExchangeUsesSourceAgnosticTrust verifies callers always use the resolver's effective bindings.
func TestTokenExchangeUsesSourceAgnosticTrust(t *testing.T) {
	issuer := newTokenExchangeIssuer(t)
	server, _ := tokenExchangeServer(t, issuer, 1)
	effective := server.config.StaticPolicy.Clients["client"].TrustBindings[0].Effective
	fake := &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: server.config.StaticPolicy.Clients["client"]}, trust: []config.EffectiveTrustBinding{*effective}}
	server.policyResolver = fake
	originalTransport := http.DefaultTransport
	http.DefaultTransport = issuer.server.Client().Transport
	server.trust = trust.NewService(server.config, fake)
	http.DefaultTransport = originalTransport
	response := tokenExchangeRequest(server, validTokenExchangeForm(issuer.sign(nil)))
	if response.Code != http.StatusOK || fake.resolveTrustCalls != 1 || len(fake.resolveClientFresh) != 1 || !fake.resolveClientFresh[0] {
		t.Fatalf("status=%d resolve_trust_calls=%d fresh=%v body=%s", response.Code, fake.resolveTrustCalls, fake.resolveClientFresh, response.Body.String())
	}
}

// TestTokenExchangeProductionPath verifies the complete HTTP, trust, and downstream signing path.
func TestTokenExchangeProductionPath(t *testing.T) {
	issuer := newTokenExchangeIssuer(t)
	server, signingKey := tokenExchangeServer(t, issuer, 1)
	var logs bytes.Buffer
	server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	response := tokenExchangeRequest(server, validTokenExchangeForm(issuer.sign(map[string]any{"run_id": json.Number("12345")})))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers=%v", response.Header())
	}
	var body struct {
		AccessToken     string          `json:"access_token"`
		IssuedTokenType string          `json:"issued_token_type"`
		TokenType       string          `json:"token_type"`
		ExpiresIn       int64           `json:"expires_in"`
		IDToken         json.RawMessage `json:"id_token"`
		RefreshToken    json.RawMessage `json:"refresh_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.AccessToken == "" || body.IssuedTokenType != idTokenType || body.TokenType != "Bearer" || body.ExpiresIn <= 0 || body.ExpiresIn > 900 {
		t.Fatalf("unexpected response: %+v", body)
	}
	if body.IDToken != nil || body.RefreshToken != nil {
		t.Fatalf("exchange returned forbidden token fields: %s", response.Body.String())
	}
	verified, err := jwt.Parse([]byte(body.AccessToken), jwt.WithKey(signingKey.Algorithm, signingKey.PublicKey), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("verify downstream token: %v", err)
	}
	groups, ok := verified.Get("groups")
	if verified.Subject() != "trusted:builder" || len(verified.Audience()) != 1 || verified.Audience()[0] != "client" || !ok {
		t.Fatalf("unexpected trusted identity claims: %v", verified)
	}
	encodedGroups, _ := json.Marshal(groups)
	if string(encodedGroups) != `["builders","release"]` || verified.JwtID() == "" {
		t.Fatalf("groups=%s jti=%q", encodedGroups, verified.JwtID())
	}
	upstreamIssuer, _ := verified.Get("upstream_issuer")
	upstreamSubject, _ := verified.Get("upstream_subject")
	if upstreamIssuer != issuer.server.URL || upstreamSubject != "upstream-user" {
		t.Fatalf("upstream provenance=%q/%q", upstreamIssuer, upstreamSubject)
	}
	if _, exists := verified.Get("sid"); exists {
		t.Fatal("trusted token unexpectedly contains sid")
	}
	output := logs.String()
	for _, safe := range []string{`"issuer_id":"local"`, `"issuer":"` + issuer.server.URL + `"`, `"client_id":"client"`, `"binding":"binding-policy-a"`, `"policy":"policy-a"`, `"run_id":"12345"`, `"result":"allowed"`} {
		if !strings.Contains(output, safe) {
			t.Errorf("safe audit field %s missing from %s", safe, output)
		}
	}
	for _, private := range []string{"upstream-user", "trusted:builder"} {
		if strings.Contains(output, private) {
			t.Errorf("audit log leaked subject %q: %s", private, output)
		}
	}
}

// TestTokenExchangeDenials verifies RFC 8693 inputs fail closed without reflecting credentials.
func TestTokenExchangeDenials(t *testing.T) {
	issuer := newTokenExchangeIssuer(t)
	ordinary, _ := tokenExchangeServer(t, issuer, 1)
	ambiguous, _ := tokenExchangeServer(t, issuer, 2)
	external := issuer.sign(nil)
	tests := []struct {
		name   string
		server *Server
		form   url.Values
	}{
		{"cross-client audience", ordinary, validTokenExchangeForm(issuer.sign(map[string]any{"aud": "other-client"}))},
		{"ambiguous bindings", ambiguous, validTokenExchangeForm(external)},
		{"unrelated parameter", ordinary, func() url.Values { v := validTokenExchangeForm(external); v.Set("scope", "openid"); return v }()},
		{"duplicate parameter", ordinary, func() url.Values {
			v := validTokenExchangeForm(external)
			v["client_id"] = []string{"client", "client"}
			return v
		}()},
		{"wrong subject token type", ordinary, func() url.Values {
			v := validTokenExchangeForm(external)
			v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
			return v
		}()},
		{"wrong requested token type", ordinary, func() url.Values {
			v := validTokenExchangeForm(external)
			v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
			return v
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := tokenExchangeRequest(test.server, test.form)
			if response.Code == http.StatusOK {
				t.Fatalf("exchange unexpectedly succeeded: %s", response.Body.String())
			}
			if strings.Contains(response.Body.String(), test.form.Get("subject_token")) {
				t.Fatal("OAuth error reflected the external token")
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] == nil {
				t.Fatalf("invalid OAuth error: %s", response.Body.String())
			}
		})
	}
}
