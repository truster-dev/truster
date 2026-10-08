// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/statedb"
	"github.com/truster-dev/truster/v3/internal/tokens"
)

// revocationProofKey holds an ES256 key and its canonical thumbprint for handler tests.
type revocationProofKey struct {
	key *ecdsa.PrivateKey
	jkt string
}

// newRevocationProofKey creates a fresh ES256 proof key.
func newRevocationProofKey(t *testing.T) revocationProofKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return revocationProofKey{key: key, jkt: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// proof signs a fresh revocation proof with the requested replay identifier.
func (k revocationProofKey) proof(t *testing.T, jti string) string {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(k.key.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(k.key.Y.FillBytes(make([]byte, 32)))
	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}})
	claims, _ := json.Marshal(map[string]any{"jti": jti, "htm": "POST", "htu": "https://issuer.example/revoke", "iat": time.Now().Unix()})
	h, p := base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(h + "." + p))
	r, s, err := ecdsa.Sign(rand.Reader, k.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// revokeServer creates a revocation handler with a real SQLite store and signer.
func revokeServer(t *testing.T) (*Server, *statedb.Store, *tokens.Signer) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	signer := tokens.NewSigner(newTestSigningKey(t), "test-kid", "https://issuer.example", time.Hour)
	cfg := &config.Config{IssuerURL: "https://issuer.example", StaticPolicy: config.StaticPolicyConfig{Clients: map[string]config.ClientConfig{
		"client":       {DPoP: config.DPoPConfig{Mode: "disabled"}},
		"other-client": {DPoP: config.DPoPConfig{Mode: "disabled"}},
	}}}
	return &Server{config: cfg, store: store, signer: signer, logger: logger, policyResolver: authpolicy.NewResolver(cfg, nil)}, store, signer
}

// createRevocableGrant inserts one active refresh family for handler tests.
func createRevocableGrant(t *testing.T, store *statedb.Store, sid, clientID string) statedb.RefreshMaterial {
	t.Helper()
	now := time.Now().UTC()
	material, err := statedb.GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	grant := statedb.RefreshGrant{SID: sid, ClientID: clientID, Email: "user@example.com", Scopes: "openid", ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err = store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	return material
}

// revokeRequest sends a canonical revocation form to the handler.
func revokeRequest(server *Server, values url.Values) *httptest.ResponseRecorder {
	return revokeRequestWithProof(server, values, "")
}

// revokeRequestWithProof sends a canonical revocation form with an optional proof.
func revokeRequestWithProof(server *Server, values url.Values, proof string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		request.Header.Set("DPoP", proof)
	}
	response := httptest.NewRecorder()
	server.HandleRevoke(response, request)
	return response
}

// TestHandleRevokeAppliesPublicClientProofPolicy verifies policy errors precede token inspection.
func TestHandleRevokeAppliesPublicClientProofPolicy(t *testing.T) {
	server, _, _ := revokeServer(t)
	key := newRevocationProofKey(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	missing := revokeRequest(server, url.Values{"token": {"unknown"}, "client_id": {"client"}})
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), `"error":"invalid_dpop_proof"`) {
		t.Fatalf("required missing = %d %q", missing.Code, missing.Body.String())
	}
	client.DPoP = config.DPoPConfig{Mode: "disabled"}
	server.config.StaticPolicy.Clients["client"] = client
	supplied := revokeRequestWithProof(server, url.Values{"token": {"unknown"}, "client_id": {"client"}}, key.proof(t, "disabled"))
	if supplied.Code != http.StatusBadRequest || !strings.Contains(supplied.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("disabled supplied = %d %q", supplied.Code, supplied.Body.String())
	}
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	request := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader("token=unknown&client_id=client"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("DPoP", key.proof(t, "one"))
	request.Header.Add("DPoP", key.proof(t, "two"))
	multiple := httptest.NewRecorder()
	server.HandleRevoke(multiple, request)
	if multiple.Code != http.StatusBadRequest || !strings.Contains(multiple.Body.String(), `"error":"invalid_dpop_proof"`) {
		t.Fatalf("multiple proofs = %d %q", multiple.Code, multiple.Body.String())
	}
}

// TestHandleRevokeDPoPBindingAndReplay verifies exact-key revocation and reservation for unknown tokens.
func TestHandleRevokeDPoPBindingAndReplay(t *testing.T) {
	server, store, _ := revokeServer(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	correct, wrong := newRevocationProofKey(t), newRevocationProofKey(t)
	now := time.Now().UTC()
	unboundMaterial := createRevocableGrant(t, store, "unbound-under-required", "client")
	if got := revokeRequestWithProof(server, url.Values{"token": {unboundMaterial.Token}, "client_id": {"client"}}, wrong.proof(t, "unbound")); got.Code != http.StatusOK {
		t.Fatalf("unbound token with proof = %d %q", got.Code, got.Body.String())
	}
	if _, _, err := store.PrepareRefresh(unboundMaterial, "client", time.Now()); err != nil {
		t.Fatalf("proof revoked unbound grant: %v", err)
	}
	material := createRevocableGrant(t, store, "bound-sid", "client")
	// Replace the bearer fixture with a bound grant for this test.
	if err := store.RevokeGrant("bound-sid", "client", "fixture", now); err != nil {
		t.Fatal(err)
	}
	boundMaterial, err := statedb.GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	grant := statedb.RefreshGrant{SID: "bound-active", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour), DPoPJKT: correct.jkt}
	if err = store.CreateRefreshGrant(grant, boundMaterial, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	_ = material
	proofless := revokeRequest(server, url.Values{"token": {boundMaterial.Token}, "client_id": {"client"}})
	if proofless.Code != http.StatusBadRequest {
		t.Fatalf("proofless bound = %d %q", proofless.Code, proofless.Body.String())
	}
	if _, _, err = store.PrepareRefresh(boundMaterial, "client", time.Now()); err != nil {
		t.Fatalf("proofless request revoked bound grant: %v", err)
	}
	wrongResponse := revokeRequestWithProof(server, url.Values{"token": {boundMaterial.Token}, "client_id": {"client"}}, wrong.proof(t, "wrong"))
	if wrongResponse.Code != http.StatusOK {
		t.Fatalf("wrong key = %d %q", wrongResponse.Code, wrongResponse.Body.String())
	}
	if _, _, err = store.PrepareRefresh(boundMaterial, "client", time.Now()); err != nil {
		t.Fatalf("wrong key revoked grant: %v", err)
	}
	proof := correct.proof(t, "reserved-on-unknown")
	if got := revokeRequestWithProof(server, url.Values{"token": {"unknown"}, "client_id": {"client"}}, proof); got.Code != http.StatusOK {
		t.Fatalf("unknown proof = %d %q", got.Code, got.Body.String())
	}
	replay := revokeRequestWithProof(server, url.Values{"token": {boundMaterial.Token}, "client_id": {"client"}}, proof)
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), `"error":"invalid_dpop_proof"`) {
		t.Fatalf("replay = %d %q", replay.Code, replay.Body.String())
	}
	if got := revokeRequestWithProof(server, url.Values{"token": {boundMaterial.Token}, "client_id": {"client"}}, correct.proof(t, "correct")); got.Code != http.StatusOK {
		t.Fatalf("correct key = %d %q", got.Code, got.Body.String())
	}
	if _, _, err = store.PrepareRefresh(boundMaterial, "client", time.Now()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("correct key did not revoke: %v", err)
	}
}

// TestHandleRevokeDPoPJWTs verifies bound access tokens and unbound ID tokens use authoritative grant binding.
func TestHandleRevokeDPoPJWTs(t *testing.T) {
	server, store, signer := revokeServer(t)
	client := server.config.StaticPolicy.Clients["client"]
	client.DPoP = config.DPoPConfig{Mode: "required", SigningAlgorithm: "ES256"}
	server.config.StaticPolicy.Clients["client"] = client
	key := newRevocationProofKey(t)
	for _, kind := range []string{"access", "id"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().UTC()
			sid := "jwt-dpop-" + kind
			material, err := statedb.GenerateRefreshMaterial()
			if err != nil {
				t.Fatal(err)
			}
			grant := statedb.RefreshGrant{SID: sid, ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour), DPoPJKT: key.jkt}
			if err = store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
				t.Fatal(err)
			}
			idToken, accessToken, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "client", SID: sid, Scopes: "openid", AuthTime: now, IDExpiry: now.Add(time.Hour), AccessExpiry: now.Add(time.Hour), DPoPJKT: key.jkt})
			if err != nil {
				t.Fatal(err)
			}
			raw := accessToken
			if kind == "id" {
				raw = idToken
			}
			response := revokeRequestWithProof(server, url.Values{"token": {raw}, "client_id": {"client"}}, key.proof(t, "jwt-"+kind))
			if response.Code != http.StatusOK || response.Body.Len() != 0 {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			if _, _, err = store.PrepareRefresh(material, "client", time.Now()); !errors.Is(err, statedb.ErrInvalidGrant) {
				t.Fatalf("grant remains active: %v", err)
			}
		})
	}
}

// TestHandleRevokeRevokesRefreshFamily verifies refresh tokens are client-bound and family-wide.
func TestHandleRevokeRevokesRefreshFamily(t *testing.T) {
	server, store, _ := revokeServer(t)
	material := createRevocableGrant(t, store, "refresh-sid", "client")

	wrongClient := revokeRequest(server, url.Values{"token": {material.Token}, "client_id": {"other-client"}})
	if wrongClient.Code != http.StatusOK || wrongClient.Body.Len() != 0 {
		t.Fatalf("wrong-client response = %d %q, want empty 200", wrongClient.Code, wrongClient.Body.String())
	}
	if _, _, err := store.PrepareRefresh(material, "client", time.Now()); err != nil {
		t.Fatalf("wrong client revoked grant: %v", err)
	}

	response := revokeRequest(server, url.Values{"token": {material.Token}, "client_id": {"client"}})
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("response = %d %q, want empty 200", response.Code, response.Body.String())
	}
	if _, _, err := store.PrepareRefresh(material, "client", time.Now()); err != statedb.ErrInvalidGrant {
		t.Fatalf("grant after revocation = %v, want ErrInvalidGrant", err)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("missing no-store headers: %v", response.Header())
	}
}

// TestHandleRevokeAcceptsJWTAndHidesUnknownTokens verifies JWT sid revocation and RFC 7009 non-disclosure.
func TestHandleRevokeAcceptsJWTAndHidesUnknownTokens(t *testing.T) {
	server, store, signer := revokeServer(t)
	material := createRevocableGrant(t, store, "jwt-sid", "client")
	_, accessToken, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "client", SID: "jwt-sid", Scopes: "openid", AuthTime: time.Now(), IDExpiry: time.Now().Add(time.Hour), AccessExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	unknown := revokeRequest(server, url.Values{"token": {"not-a-token"}, "client_id": {"client"}})
	if unknown.Code != http.StatusOK || unknown.Body.Len() != 0 {
		t.Fatalf("unknown-token response = %d %q, want empty 200", unknown.Code, unknown.Body.String())
	}
	response := revokeRequest(server, url.Values{"token": {accessToken}, "client_id": {"client"}})
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("JWT response = %d %q, want empty 200", response.Code, response.Body.String())
	}
	if _, _, err = store.PrepareRefresh(material, "client", time.Now()); err != statedb.ErrInvalidGrant {
		t.Fatalf("grant after JWT revocation = %v, want ErrInvalidGrant", err)
	}
}

// TestHandleRevokeAcceptsIDToken verifies ID tokens revoke their refresh family.
func TestHandleRevokeAcceptsIDToken(t *testing.T) {
	server, store, signer := revokeServer(t)
	material := createRevocableGrant(t, store, "id-token-sid", "client")
	idToken, _, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "client", SID: "id-token-sid", Scopes: "openid", AuthTime: time.Now(), IDExpiry: time.Now().Add(time.Hour), AccessExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	response := revokeRequest(server, url.Values{"token": {idToken}, "client_id": {"client"}})
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("ID token response = %d %q, want empty 200", response.Code, response.Body.String())
	}
	if _, _, err = store.PrepareRefresh(material, "client", time.Now()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("grant after ID token revocation = %v", err)
	}
}

// TestHandleRevokeRejectsMalformedRequests verifies the strict RFC 7009 HTTP boundary.
func TestHandleRevokeRejectsMalformedRequests(t *testing.T) {
	server, _, _ := revokeServer(t)
	tests := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
	}{
		{name: "wrong method", method: http.MethodGet, target: "/revoke", contentType: "application/x-www-form-urlencoded", body: "token=x&client_id=client"},
		{name: "query string", method: http.MethodPost, target: "/revoke?token=x", contentType: "application/x-www-form-urlencoded", body: "token=x&client_id=client"},
		{name: "wrong content type", method: http.MethodPost, target: "/revoke", contentType: "application/json", body: `{}`},
		{name: "missing token", method: http.MethodPost, target: "/revoke", contentType: "application/x-www-form-urlencoded", body: "client_id=client"},
		{name: "duplicate client", method: http.MethodPost, target: "/revoke", contentType: "application/x-www-form-urlencoded", body: "token=x&client_id=client&client_id=other"},
		{name: "DPoP thumbprint", method: http.MethodPost, target: "/revoke", contentType: "application/x-www-form-urlencoded", body: "token=x&client_id=client&dpop_jkt=thumbprint"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			server.HandleRevoke(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_request"`) {
				t.Fatalf("response = %d %q, want invalid_request", response.Code, response.Body.String())
			}
		})
	}
}
