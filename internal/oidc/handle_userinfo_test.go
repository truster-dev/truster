// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/statedb"
	"github.com/truster-dev/truster/v3/internal/tokens"
)

// TestHandleUserInfoDPoP verifies bound-token scheme, key, ath, replay, and header enforcement.
func TestHandleUserInfoDPoP(t *testing.T) {
	issuer := "https://issuer.example"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(t.TempDir()+"/state.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	key, wrong := newEndpointProofKey(t, "ES512"), newEndpointProofKey(t, "ES512")
	cfg := &config.Config{IssuerURL: issuer, StaticPolicy: config.StaticPolicyConfig{Clients: map[string]config.ClientConfig{"client": {DPoP: config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES512"}}}}}
	signer := tokens.NewSigner(newTestSigningKey(t), "kid", issuer, time.Hour)
	server := &Server{config: cfg, store: store, signer: signer, policyResolver: authpolicy.NewResolver(cfg, nil), logger: logger}
	now := time.Now()
	_, access, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "client", Scopes: "openid", AuthTime: now, IDExpiry: now.Add(time.Hour), AccessExpiry: now.Add(time.Hour), DPoPJKT: key.jkt})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(access))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	send := func(scheme string, proofs ...string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		request.Header.Set("Authorization", scheme+" "+access)
		for _, proof := range proofs {
			request.Header.Add("DPoP", proof)
		}
		response := httptest.NewRecorder()
		server.HandleUserInfo(response, request)
		return response
	}
	if response := send("Bearer"); response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("Bearer response=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
	proof := key.proof(t, endpointProofOptions{Method: http.MethodGet, URL: issuer + "/userinfo", ATH: ath, IAT: now, JTI: "userinfo-valid"})
	if response := send("DPoP", proof); response.Code != http.StatusOK {
		t.Fatalf("valid response=%d body=%s", response.Code, response.Body.String())
	}
	invalidProofs := []struct {
		name, proof, challenge string
	}{
		{"wrong ath", key.proof(t, endpointProofOptions{Method: http.MethodGet, URL: issuer + "/userinfo", ATH: "wrong", IAT: now, JTI: "wrong-ath"}), `DPoP error="invalid_dpop_proof", algs="ES256 ES512"`},
		{"wrong method", key.proof(t, endpointProofOptions{Method: http.MethodPost, URL: issuer + "/userinfo", ATH: ath, IAT: now, JTI: "wrong-method"}), `DPoP error="invalid_dpop_proof", algs="ES256 ES512"`},
		{"wrong key", wrong.proof(t, endpointProofOptions{Method: http.MethodGet, URL: issuer + "/userinfo", ATH: ath, IAT: now, JTI: "wrong-key"}), `DPoP error="invalid_token", algs="ES256 ES512"`},
		{"replay", proof, `DPoP error="invalid_dpop_proof", algs="ES256 ES512"`},
	}
	for _, test := range invalidProofs {
		response := send("DPoP", test.proof)
		if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != test.challenge {
			t.Errorf("%s response=%d challenge=%q", test.name, response.Code, response.Header().Get("WWW-Authenticate"))
		}
	}
	if response := send("DPoP", proof, proof); response.Code != http.StatusBadRequest || response.Header().Get("WWW-Authenticate") != `DPoP error="invalid_request", algs="ES256 ES512"` {
		t.Fatalf("duplicate headers status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
	malformed := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	malformed.Header.Set("Authorization", "DPoP")
	malformedResponse := httptest.NewRecorder()
	server.HandleUserInfo(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest || malformedResponse.Header().Get("WWW-Authenticate") != `DPoP error="invalid_request", algs="ES256 ES512"` {
		t.Fatalf("malformed authorization status=%d challenge=%q", malformedResponse.Code, malformedResponse.Header().Get("WWW-Authenticate"))
	}
}

func TestHandleUserInfoVerifiesToken(t *testing.T) {
	issuer := "https://test.example.com"
	signingKey := newTestSigningKey(t)
	signer := tokens.NewSigner(signingKey, "test-kid", issuer, time.Hour)
	server := &Server{
		signer: signer,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError,
		})),
	}

	_, validToken, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", EmailVerified: false, ClientID: "test-client", Groups: []string{"users"}, Scopes: "openid email", AuthTime: time.Now(), IDExpiry: time.Now().Add(time.Hour), AccessExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("failed to sign valid token: %v", err)
	}
	forgedSigner := tokens.NewSigner(newTestSigningKey(t), "test-kid", issuer, time.Hour)
	forgedToken, err := forgedSigner.SignIDToken("attacker@example.com", true, "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign forged token: %v", err)
	}
	expiredSigner := tokens.NewSigner(signingKey, "test-kid", issuer, -time.Minute)
	expiredToken, err := expiredSigner.SignIDToken("user@example.com", true, "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}
	wrongIssuerSigner := tokens.NewSigner(signingKey, "test-kid", "https://attacker.example.com", time.Hour)
	wrongIssuerToken, err := wrongIssuerSigner.SignIDToken("user@example.com", true, "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign wrong-issuer token: %v", err)
	}

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{name: "valid token", token: validToken, wantStatus: http.StatusOK},
		{name: "forged token", token: forgedToken, wantStatus: http.StatusUnauthorized},
		{name: "expired token", token: expiredToken, wantStatus: http.StatusUnauthorized},
		{name: "wrong issuer", token: wrongIssuerToken, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			response := httptest.NewRecorder()

			server.HandleUserInfo(response, req)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.name == "valid token" && !strings.Contains(response.Body.String(), `"email_verified":false`) {
				t.Fatalf("userinfo did not preserve email_verified=false: %s", response.Body.String())
			}
		})
	}
}

func newTestSigningKey(t *testing.T) *tokens.SigningKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	return &tokens.SigningKey{
		Algorithm:  jwa.EdDSA,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

// TestHandleUserInfoKeepsBearerTokenAfterDPoPBecomesRequired verifies cnf remains authoritative.
func TestHandleUserInfoKeepsBearerTokenAfterDPoPBecomesRequired(t *testing.T) {
	issuer := "https://test.example.com"
	signer := tokens.NewSigner(newTestSigningKey(t), "kid", issuer, time.Hour)
	cfg := &config.Config{IssuerURL: issuer, StaticPolicy: config.StaticPolicyConfig{Clients: map[string]config.ClientConfig{
		"client": {DPoP: config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}},
	}}}
	server := &Server{config: cfg, signer: signer, policyResolver: authpolicy.NewResolver(cfg, nil), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	now := time.Now()
	_, accessToken, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "client", Scopes: "openid", AuthTime: now, IDExpiry: now.Add(time.Hour), AccessExpiry: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response := httptest.NewRecorder()
	server.HandleUserInfo(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d, challenge = %q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
}

// TestAccessAuthenticationChallenges verifies exact protected-resource challenge syntax.
func TestAccessAuthenticationChallenges(t *testing.T) {
	tests := []struct {
		name      string
		failure   accessAuthError
		challenge string
	}{
		{"missing credentials", accessAuthError{status: 401, scheme: "Bearer"}, "Bearer"},
		{"known DPoP client", accessAuthError{status: 401, scheme: "DPoP", code: "invalid_dpop_proof", alg: "ES256"}, `DPoP error="invalid_dpop_proof", algs="ES256"`},
		{"pre-client DPoP", accessAuthError{status: 401, scheme: "DPoP", code: "invalid_dpop_proof"}, `DPoP error="invalid_dpop_proof", algs="ES256 ES512"`},
		{"bearer scope", accessAuthError{status: 403, scheme: "Bearer", code: "insufficient_scope"}, `Bearer error="insufficient_scope"`},
		{"DPoP scope", accessAuthError{status: 403, scheme: "DPoP", code: "insufficient_scope", alg: "ES256"}, `DPoP error="insufficient_scope", algs="ES256"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeAccessAuthError(response, &test.failure)
			if response.Code != test.failure.status || response.Header().Get("WWW-Authenticate") != test.challenge {
				t.Fatalf("status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}
