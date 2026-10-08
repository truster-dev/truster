// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/statedb"
	"github.com/truster-dev/truster/v3/internal/tokens"
	"github.com/truster-dev/truster/v3/internal/upstream"
)

func TestHandleToken_RequireUserGroupsFromPolicy(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	signingKey := &tokens.SigningKey{
		Algorithm:  jwa.EdDSA,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	signer := tokens.NewSigner(signingKey, "test-kid", "https://test.example.com", time.Hour)

	tests := []struct {
		name                              string
		policyRequireUserGroupsFromPolicy *bool
		clientRequireUserGroupsFromPolicy *bool
		userGroups                        []string
		expectSuccess                     bool
		expectedError                     string
	}{
		{
			name:                              "policy true, client unset, empty groups - reject",
			policyRequireUserGroupsFromPolicy: boolPtr(true),
			clientRequireUserGroupsFromPolicy: nil,
			userGroups:                        []string{},
			expectSuccess:                     false,
			expectedError:                     "access_denied",
		},
		{
			name:                              "policy true, client false, empty groups - allow",
			policyRequireUserGroupsFromPolicy: boolPtr(true),
			clientRequireUserGroupsFromPolicy: boolPtr(false),
			userGroups:                        []string{},
			expectSuccess:                     true,
		},
		{
			name:                              "policy false, client true, empty groups - reject",
			policyRequireUserGroupsFromPolicy: boolPtr(false),
			clientRequireUserGroupsFromPolicy: boolPtr(true),
			userGroups:                        []string{},
			expectSuccess:                     false,
			expectedError:                     "access_denied",
		},
		{
			name:                              "policy false, client unset, empty groups - allow",
			policyRequireUserGroupsFromPolicy: boolPtr(false),
			clientRequireUserGroupsFromPolicy: nil,
			userGroups:                        []string{},
			expectSuccess:                     true,
		},
		{
			name:                              "policy nil (default true), client unset, empty groups - reject",
			policyRequireUserGroupsFromPolicy: nil,
			clientRequireUserGroupsFromPolicy: nil,
			userGroups:                        []string{},
			expectSuccess:                     false,
			expectedError:                     "access_denied",
		},
		{
			name:                              "policy true, client unset, with groups - allow",
			policyRequireUserGroupsFromPolicy: boolPtr(true),
			clientRequireUserGroupsFromPolicy: nil,
			userGroups:                        []string{"admins"},
			expectSuccess:                     true,
		},
		{
			name:                              "policy false, client false, with groups - allow",
			policyRequireUserGroupsFromPolicy: boolPtr(false),
			clientRequireUserGroupsFromPolicy: boolPtr(false),
			userGroups:                        []string{"developers"},
			expectSuccess:                     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				IssuerURL:      "https://test.example.com",
				AccessTokenTTL: config.Duration(time.Hour),
				IDTokenTTL:     config.Duration(time.Hour),
				StaticPolicy: config.StaticPolicyConfig{
					RequireUserGroupsFromPolicy: tt.policyRequireUserGroupsFromPolicy,
					Clients: map[string]config.ClientConfig{
						"test-client": {
							RequireUserGroupsFromPolicy: tt.clientRequireUserGroupsFromPolicy,
							UserGroupMapping:            "test-override",
						},
					},
					UserGroupMappings: map[string]map[string][]string{
						"test-override": {"user@example.com": tt.userGroups},
					},
				},
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
			if err != nil {
				t.Fatalf("failed to create storage: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					t.Errorf("failed to close store: %v", err)
				}
			}()

			authCodeMgr, err := NewAuthCodeManager(store)
			if err != nil {
				t.Fatalf("failed to create auth code manager: %v", err)
			}

			srv := NewServer(cfg, nil, authCodeMgr, signer, []byte("{}"), logger, store, nil, nil, nil, nil, nil, nil, nil)

			verifier := "test-verifier-dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
			hash := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(hash[:])

			authCode, err := authCodeMgr.GenerateCode(AuthCodePayload{
				ClientID:      "test-client",
				Email:         "user@example.com",
				RedirectURI:   "http://localhost/callback",
				CodeChallenge: challenge,
				Nonce:         "test-nonce",
			})
			if err != nil {
				t.Fatalf("failed to generate auth code: %v", err)
			}

			formData := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"client_id":     {"test-client"},
				"redirect_uri":  {"http://localhost/callback"},
				"code_verifier": {verifier},
			}

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			srv.HandleToken(w, req)

			if tt.expectSuccess {
				if w.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
				}

				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if _, ok := response["id_token"]; !ok {
					t.Error("expected id_token in response")
				}
			} else {
				if w.Code != http.StatusForbidden {
					t.Errorf("expected status 403, got %d", w.Code)
				}

				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}

				if response["error"] != tt.expectedError {
					t.Errorf("expected error %q, got %q", tt.expectedError, response["error"])
				}
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// refreshTokenServer creates a token endpoint configured for one direct-email connector.
func refreshTokenServer(t *testing.T) (*Server, *statedb.Store, *AuthCodeManager, []byte, string) {
	t.Helper()
	path := t.TempDir() + "/test.db"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := statedb.NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := NewAuthCodeManager(store)
	if err != nil {
		t.Fatal(err)
	}
	requireUserGroupsFromPolicy := false
	cfg := &config.Config{
		IssuerURL:           "https://issuer.example",
		AccessTokenTTL:      config.Duration(15 * time.Minute),
		IDTokenTTL:          config.Duration(10 * time.Minute),
		UserLoginConnectors: map[string]config.ConnectorConfig{"provider": {Type: "email"}},
		StaticPolicy: config.StaticPolicyConfig{
			RequireUserGroupsFromPolicy: &requireUserGroupsFromPolicy,
			Clients: map[string]config.ClientConfig{
				"client": {RefreshTokens: config.RefreshTokenConfig{Enabled: true, SessionIdleTTL: config.Duration(time.Hour), SessionAbsoluteTTL: config.Duration(4 * time.Hour)}},
			},
		},
	}
	key := []byte("01234567890123456789012345678901")
	signer := tokens.NewSigner(newTestSigningKey(t), "kid", cfg.IssuerURL, time.Hour)
	return NewServer(cfg, nil, manager, signer, nil, logger, store, nil, nil, nil, nil, nil, key, nil), store, manager, key, path
}

// exchangeCodeRequest sends a valid authorization-code token request.
func exchangeCodeRequest(server *Server, code, verifier string) *httptest.ResponseRecorder {
	values := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleToken(response, request)
	return response
}

// TestHandleTokenRedeemsDPoPBoundCode verifies proof failures preserve a bound code and successful JWT shaping.
func TestHandleTokenRedeemsDPoPBoundCode(t *testing.T) {
	server, store, manager, _, _ := refreshTokenServer(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP, client.RefreshTokens.Enabled = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}, false
	server.config.StaticPolicy.Clients["client"] = client
	key, wrong := newEndpointProofKey(t, "ES256"), newEndpointProofKey(t, "ES256")
	verifier := strings.Repeat("a", 43)
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: computeChallenge(verifier), Email: "user@example.com", Scopes: "openid", AuthTime: time.Now(), DPoPJKT: key.jkt})
	if err != nil {
		t.Fatal(err)
	}
	send := func(proofs ...string) *httptest.ResponseRecorder {
		values := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}}
		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, proof := range proofs {
			request.Header.Add("DPoP", proof)
		}
		response := httptest.NewRecorder()
		server.HandleToken(response, request)
		return response
	}
	now := time.Now()
	valid := key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/token", IAT: now, JTI: "valid"})
	tests := []struct {
		name, wantError string
		proofs          []string
	}{{"missing", "invalid_dpop_proof", nil}, {"wrong key", "invalid_grant", []string{wrong.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/token", IAT: now, JTI: "wrong"})}}, {"stale", "invalid_dpop_proof", []string{key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/token", IAT: now.Add(-time.Hour), JTI: "stale"})}}, {"wrong target", "invalid_dpop_proof", []string{key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/other", IAT: now, JTI: "target"})}}, {"duplicate headers", "invalid_dpop_proof", []string{valid, valid}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if response := send(test.proofs...); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"`+test.wantError+`"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if _, peekErr := store.PeekAuthCode(code, time.Now()); peekErr != nil {
				t.Fatalf("proof failure consumed code: %v", peekErr)
			}
		})
	}
	response := send(valid)
	if response.Code != http.StatusOK {
		t.Fatalf("valid status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type=%v", body["token_type"])
	}
	access, err := server.signer.VerifyToken(body["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if jkt, thumbErr := tokens.DPoPThumbprint(access); thumbErr != nil || jkt != key.jkt {
		t.Fatalf("access cnf.jkt=%q err=%v", jkt, thumbErr)
	}
	id, err := server.signer.VerifyToken(body["id_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := id.Get("cnf"); present {
		t.Fatal("ID token unexpectedly contains cnf")
	}
}

// TestHandleTokenRejectsDirectCodeAfterPARBecomesRequired verifies current policy before consumption.
func TestHandleTokenRejectsDirectCodeAfterPARBecomesRequired(t *testing.T) {
	server, store, manager, _, _ := refreshTokenServer(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.RefreshTokens.Enabled = false
	client.RequirePAR = true
	server.config.StaticPolicy.Clients["client"] = client
	verifier := strings.Repeat("p", 43)
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: computeChallenge(verifier), Email: "user@example.com", Scopes: "openid", AuthTime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	response := exchangeCodeRequest(server, code, verifier)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_grant") {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if _, err = store.PeekAuthCode(code, time.Now()); err != nil {
		t.Fatalf("policy rejection consumed code: %v", err)
	}
}

// TestDynamicCodeRedemptionPreservesCodeUntilDefinitiveAuthorization verifies retry-safe SQLite redemption.
func TestDynamicCodeRedemptionPreservesCodeUntilDefinitiveAuthorization(t *testing.T) {
	server, store, manager, _, _ := refreshTokenServer(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.RefreshTokens.Enabled = false
	fake := &fakePolicyResolver{
		client:      authpolicy.ResolvedClient{Config: client},
		userErrors:  []error{&authpolicy.IndeterminateError{Err: context.DeadlineExceeded}, nil},
		userResults: []authpolicy.ResolvedUser{{}, {Groups: []string{"current-group"}}},
	}
	server.policyResolver = fake
	verifier := "test-verifier-dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", Email: "user@example.com", RedirectURI: "https://client.example/callback", CodeChallenge: base64.RawURLEncoding.EncodeToString(hash[:]), Scopes: "openid groups", AuthTime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	first := exchangeCodeRequest(server, code, verifier)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	if _, err = store.PeekAuthCode(code, time.Now()); err != nil {
		t.Fatalf("temporary failure consumed code: %v", err)
	}
	second := exchangeCodeRequest(server, code, verifier)
	if second.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", second.Code, second.Body.String())
	}
	if _, err = store.PeekAuthCode(code, time.Now()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("successful redemption left code: %v", err)
	}
	var response struct {
		IDToken string `json:"id_token"`
	}
	if err = json.Unmarshal(second.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	verified, err := server.signer.VerifyToken(response.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := verified.Get("groups")
	encoded, _ := json.Marshal(groups)
	if string(encoded) != `["current-group"]` {
		t.Fatalf("groups=%s", encoded)
	}
}

// TestDynamicCodeRedemptionDenialIssuesNothing verifies definitive denial consumes no code or token state.
func TestDynamicCodeRedemptionDenialIssuesNothing(t *testing.T) {
	server, store, manager, _, _ := refreshTokenServer(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.RefreshTokens.Enabled = false
	server.policyResolver = &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: client}, userErrors: []error{authpolicy.ErrDenied}}
	verifier := "test-verifier-dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", Email: "user@example.com", RedirectURI: "https://client.example/callback", CodeChallenge: base64.RawURLEncoding.EncodeToString(hash[:]), Scopes: "openid", AuthTime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	response := exchangeCodeRequest(server, code, verifier)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "id_token") || strings.Contains(response.Body.String(), "access_token") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err = store.PeekAuthCode(code, time.Now()); err != nil {
		t.Fatalf("denial unexpectedly consumed code: %v", err)
	}
}

// exitResponseWriter terminates its process when the token response body is written.
type exitResponseWriter struct{ header http.Header }

// Header returns the response headers accumulated before process termination.
func (w *exitResponseWriter) Header() http.Header { return w.header }

// WriteHeader accepts headers so termination occurs specifically during body delivery.
func (*exitResponseWriter) WriteHeader(int) {}

// Write simulates losing the process and response after refresh rotation commits.
func (*exitResponseWriter) Write([]byte) (int, error) {
	os.Exit(0)
	return 0, nil
}

// responseLossServer opens a token endpoint over an existing direct-email refresh database.
func responseLossServer(t *testing.T, path string) (*Server, *statedb.Store) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := statedb.NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	requireUserGroupsFromPolicy := false
	cfg := &config.Config{
		IssuerURL:           "https://issuer.example",
		AccessTokenTTL:      config.Duration(15 * time.Minute),
		IDTokenTTL:          config.Duration(10 * time.Minute),
		UserLoginConnectors: map[string]config.ConnectorConfig{"provider": {Type: "email"}},
		StaticPolicy: config.StaticPolicyConfig{
			RequireUserGroupsFromPolicy: &requireUserGroupsFromPolicy,
			Clients:                     map[string]config.ClientConfig{"client": {RefreshTokens: config.RefreshTokenConfig{Enabled: true}}},
		},
	}
	signer := tokens.NewSigner(newTestSigningKey(t), "kid", cfg.IssuerURL, time.Hour)
	return NewServer(cfg, nil, nil, signer, nil, logger, store, nil, nil, nil, nil, nil, nil, nil), store
}

// TestResponseWriteCrashProcess exits from the production HTTP response writer after commit.
func TestResponseWriteCrashProcess(t *testing.T) {
	path := os.Getenv("TRUSTER_RESPONSE_CRASH_DB")
	if path == "" {
		t.Skip("subprocess helper")
	}
	server, _ := responseLossServer(t, path)
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {os.Getenv("TRUSTER_RESPONSE_CRASH_TOKEN")}, "client_id": {"client"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.HandleToken(&exitResponseWriter{header: make(http.Header)}, request)
	t.Fatal("token response body was not written")
}

// TestResponseWriteLossReplaysAndRevokes verifies a lost committed response requires re-login.
func TestResponseWriteLossReplaysAndRevokes(t *testing.T) {
	path := t.TempDir() + "/response-loss.db"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := statedb.NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	material, err := statedb.GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	grant := statedb.RefreshGrant{SID: "response-loss", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "provider", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err = store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestResponseWriteCrashProcess$")
	command.Env = append(os.Environ(), "TRUSTER_RESPONSE_CRASH_DB="+path, "TRUSTER_RESPONSE_CRASH_TOKEN="+material.Token)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("response-write crash helper: %v\n%s", runErr, output)
	}
	server, store := responseLossServer(t, path)
	t.Cleanup(func() { _ = store.Close() })
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {material.Token}, "client_id": {"client"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleToken(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("lost response retry = %d %q", response.Code, response.Body.String())
	}
	grants, err := store.ListActiveGrants("user@example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("replayed family remained active: %#v", grants)
	}
}

// TestHandleTokenIssuesAndRotatesDirectRefresh verifies authorization-code wiring into the refresh domain.
func TestHandleTokenIssuesAndRotatesDirectRefresh(t *testing.T) {
	server, _, manager, _, _ := refreshTokenServer(t)
	verifier := strings.Repeat("a", 43)
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: computeChallenge(verifier), Email: "user@example.com", EmailVerified: true, Scopes: "openid email", RefreshMode: "session", AuthTime: time.Now().UTC(), ConnectorID: "provider", UpstreamSubject: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	response := exchangeCodeRequest(server, code, verifier)
	if response.Code != http.StatusOK {
		t.Fatalf("code exchange = %d %q", response.Code, response.Body.String())
	}
	var issued map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	refreshToken, ok := issued["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("missing refresh token: %#v", issued)
	}
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {"client"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rotated := httptest.NewRecorder()
	server.HandleToken(rotated, request)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), refreshToken) {
		t.Fatalf("refresh exchange = %d %q", rotated.Code, rotated.Body.String())
	}
}

// TestHandleTokenRotatesDPoPBoundDirectRefresh verifies proof failures do not rotate or revoke a direct family.
func TestHandleTokenRotatesDPoPBoundDirectRefresh(t *testing.T) {
	server, store, _, _, _ := refreshTokenServer(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES512"}
	server.config.StaticPolicy.Clients["client"] = client
	key, wrong := newEndpointProofKey(t, "ES512"), newEndpointProofKey(t, "ES512")
	now := time.Now().UTC()
	create := func(sid string) statedb.RefreshMaterial {
		material, err := statedb.GenerateRefreshMaterial()
		if err != nil {
			t.Fatal(err)
		}
		grant := statedb.RefreshGrant{SID: sid, ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "provider", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(3 * time.Hour), DPoPJKT: key.jkt}
		if err = store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
			t.Fatal(err)
		}
		return material
	}
	send := func(material statedb.RefreshMaterial, proofs ...string) *httptest.ResponseRecorder {
		values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {material.Token}, "client_id": {"client"}}
		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, proof := range proofs {
			request.Header.Add("DPoP", proof)
		}
		response := httptest.NewRecorder()
		server.HandleToken(response, request)
		return response
	}
	material := create("bound-direct")
	wrongProof := wrong.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/token", IAT: now, JTI: "refresh-wrong"})
	for _, proofs := range [][]string{nil, {wrongProof}} {
		if response := send(material, proofs...); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid proof status=%d body=%s", response.Code, response.Body.String())
		}
		if _, _, err := store.PrepareRefresh(material, "client", time.Now()); err != nil {
			t.Fatalf("invalid proof changed family: %v", err)
		}
	}
	replayedProof := key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/token", IAT: now, JTI: "refresh-replay"})
	sacrificial := create("replay-source")
	if response := send(sacrificial, replayedProof); response.Code != http.StatusOK {
		t.Fatalf("replay source status=%d body=%s", response.Code, response.Body.String())
	}
	if response := send(material, replayedProof); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_dpop_proof") {
		t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
	}
	if _, _, err := store.PrepareRefresh(material, "client", time.Now()); err != nil {
		t.Fatalf("replayed proof changed family: %v", err)
	}
	valid := key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: "https://issuer.example/token", IAT: time.Now(), JTI: "refresh-valid"})
	response := send(material, valid)
	if response.Code != http.StatusOK {
		t.Fatalf("valid status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["token_type"] != "DPoP" || body["refresh_token"] == material.Token {
		t.Fatalf("rotation response=%#v", body)
	}
	access, err := server.signer.VerifyToken(body["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if jkt, thumbErr := tokens.DPoPThumbprint(access); thumbErr != nil || jkt != key.jkt {
		t.Fatalf("rotated access cnf.jkt=%q err=%v", jkt, thumbErr)
	}
}

// TestHandleTokenRefreshOutagesAreRetryable distinguishes unavailable dependencies from invalid grants.
func TestHandleTokenRefreshOutagesAreRetryable(t *testing.T) {
	send := func(server *Server, token string) *httptest.ResponseRecorder {
		values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {"client"}}
		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		server.HandleToken(response, request)
		return response
	}
	create := func(t *testing.T, store *statedb.Store, sid string) statedb.RefreshMaterial {
		t.Helper()
		material, err := statedb.GenerateRefreshMaterial()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		grant := statedb.RefreshGrant{SID: sid, ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "provider", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
		if err = store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
			t.Fatal(err)
		}
		return material
	}
	t.Run("storage", func(t *testing.T) {
		server, store, _, _, _ := refreshTokenServer(t)
		material := create(t, store, "storage-outage")
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		response := send(server, material.Token)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "temporarily_unavailable") {
			t.Fatalf("storage outage = %d %q", response.Code, response.Body.String())
		}
	})
	t.Run("policy", func(t *testing.T) {
		server, store, _, _, _ := refreshTokenServer(t)
		material := create(t, store, "policy-outage")
		server.policyResolver = &fakePolicyResolver{clientErrors: []error{errors.New("policy unavailable")}}
		response := send(server, material.Token)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "temporarily_unavailable") {
			t.Fatalf("policy outage = %d %q", response.Code, response.Body.String())
		}
		if _, _, err := store.PrepareRefresh(material, "client", time.Now()); err != nil {
			t.Fatalf("policy outage changed grant: %v", err)
		}
	})
}

// TestHandleTokenRejectsCredentialProvenanceDrift verifies provider credentials cannot become local grants.
func TestHandleTokenRejectsCredentialProvenanceDrift(t *testing.T) {
	server, store, manager, key, _ := refreshTokenServer(t)
	verifier := strings.Repeat("a", 43)
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: computeChallenge(verifier), Email: "user@example.com", EmailVerified: true, Scopes: "openid", RefreshMode: "session", AuthTime: time.Now().UTC(), ConnectorID: "provider", UpstreamSubject: "subject"})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := json.Marshal(upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := statedb.EncryptTemporaryCredential(key, code, "client", "provider", credential)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveFlowCredential("", code, "client", "provider", nonce, ciphertext, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	response := exchangeCodeRequest(server, code, verifier)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_grant"`) || strings.Contains(response.Body.String(), "refresh_token") {
		t.Fatalf("drift response = %d %q", response.Code, response.Body.String())
	}
}

// TestHandleTokenRejectsInvalidProtocolRequests verifies the strict public-client boundary.
func TestHandleTokenRejectsInvalidProtocolRequests(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server := &Server{logger: logger}
	tests := []struct {
		name, method, target, contentType, body, authorizationHeader, wantError string
		wantStatus                                                              int
	}{
		{name: "wrong method", method: http.MethodGet, target: "/token", contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusMethodNotAllowed, wantError: "invalid_request"},
		{name: "query parameters", method: http.MethodPost, target: "/token?grant_type=refresh_token", contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "wrong content type", method: http.MethodPost, target: "/token", contentType: "application/json", body: `{}`, wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "missing grant type", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "unsupported grant type", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=password", wantStatus: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "duplicate parameter", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&grant_type=authorization_code", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "basic authentication", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token", authorizationHeader: "Basic Y2xpZW50OnNlY3JldA==", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "client secret", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&client_secret=secret", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "empty client secret", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&client_secret=", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "DPoP thumbprint", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=password&dpop_jkt=thumbprint", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "refresh token on code grant", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=authorization_code&refresh_token=token", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "code on refresh grant", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&code=code", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Authorization", test.authorizationHeader)
			response := httptest.NewRecorder()
			server.HandleToken(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, test.wantStatus, response.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["error"] != test.wantError {
				t.Fatalf("error = %v, want %s", payload["error"], test.wantError)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("missing no-store headers: %v", response.Header())
			}
		})
	}
}
