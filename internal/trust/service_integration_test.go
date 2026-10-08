// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
)

// dynamicPolicyResolver supplies one database-style issuer and binding to the verifier.
type dynamicPolicyResolver struct {
	issuer  config.TrustIssuerConfig
	binding config.EffectiveTrustBinding
	calls   int
}

// ResolveClient returns a database-style client handle opaque to this test seam.
func (r *dynamicPolicyResolver) ResolveClient(context.Context, string, bool) (authpolicy.ResolvedClient, error) {
	r.calls++
	return authpolicy.ResolvedClient{}, nil
}

// ResolveTrustIssuer returns the approved issuer only for its exact URL.
func (r *dynamicPolicyResolver) ResolveTrustIssuer(_ context.Context, _ authpolicy.ResolvedClient, issuerURL string) (authpolicy.ResolvedTrustIssuer, error) {
	r.calls++
	if issuerURL != r.issuer.IssuerURL {
		return authpolicy.ResolvedTrustIssuer{}, authpolicy.ErrDenied
	}
	return authpolicy.ResolvedTrustIssuer{ID: "dynamic", Config: r.issuer, Dynamic: true}, nil
}

// ResolveTrustBindings returns the current effective binding.
func (r *dynamicPolicyResolver) ResolveTrustBindings(context.Context, authpolicy.ResolvedClient, authpolicy.ResolvedTrustIssuer) ([]config.EffectiveTrustBinding, error) {
	r.calls++
	return []config.EffectiveTrustBinding{r.binding}, nil
}

// tlsIssuer is an exact local OIDC discovery, JWKS, and JWT-signing fixture.
type tlsIssuer struct {
	t        *testing.T
	server   *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	outage   bool
	redirect string
}

// newTLSIssuer starts a local TLS issuer with a fresh RSA key.
func newTLSIssuer(t *testing.T) *tlsIssuer {
	t.Helper()
	f := &tlsIssuer{t: t, kid: "current"}
	f.rotate()
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

// serveHTTP serves only the exact discovery and JWKS resources.
func (f *tlsIssuer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if f.outage {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if f.redirect != "" && r.URL.Path == "/.well-known/openid-configuration" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL, "jwks_uri": f.server.URL + "/jwks"})
	case "/jwks":
		public, err := jwk.FromRaw(&f.key.PublicKey)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = public.Set(jwk.KeyIDKey, f.kid)
		_ = public.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk.Key{public}})
	default:
		http.NotFound(w, r)
	}
}

// rotate replaces the fixture signing key and key ID.
func (f *tlsIssuer) rotate() {
	f.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.key, f.kid = key, "kid-"+time.Now().Format("150405.000000000")
}

// sign signs configurable claims and protected headers.
func (f *tlsIssuer) sign(claims map[string]any, options ...any) string {
	f.t.Helper()
	now := time.Now().UTC()
	defaults := map[string]any{"iss": f.server.URL, "sub": "upstream-user", "aud": "client", "iat": now, "exp": now.Add(time.Hour), "repository": "acme/repo"}
	for k, v := range claims {
		if v == nil {
			delete(defaults, k)
			continue
		}
		defaults[k] = v
	}
	token := jwt.New()
	for k, v := range defaults {
		if err := token.Set(k, v); err != nil {
			f.t.Fatal(err)
		}
	}
	alg, key, kid := jwa.RS256, any(f.key), f.kid
	for _, option := range options {
		switch value := option.(type) {
		case jwa.SignatureAlgorithm:
			alg = value
		case *rsa.PrivateKey:
			key = value
		case string:
			kid = value
		}
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, kid)
	signed, err := jwt.Sign(token, jwt.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(signed)
}

// serviceForIssuer creates a production verifier with compiled policy schemas.
func serviceForIssuer(t *testing.T, issuer *tlsIssuer, policies ...string) *Service {
	t.Helper()
	bindings := make([]config.TrustBindingConfig, len(policies))
	policyMap := make(map[string]config.TrustPolicyConfig, len(policies))
	for i, repository := range policies {
		name := "policy" + string(rune('A'+i))
		policyMap[name] = config.TrustPolicyConfig{Issuer: "local", Subject: "trusted:user", Groups: []string{"builders"}, Claims: map[string]json.RawMessage{"repository": json.RawMessage(`{"const":` + mustJSON(t, repository) + `}`)}}
		bindings[i] = config.TrustBindingConfig{ID: "binding-" + name, TrustPolicy: name}
	}
	cfg := &config.Config{
		IssuerURL:           "https://downstream.example",
		HTTPListenAddr:      ":8080",
		Secrets:             config.SecretsConfig{Provider: "env", SigningKeyName: "KEY"},
		UserLoginConnectors: map[string]config.ConnectorConfig{"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "GOOGLE_KEY"}},
		ServiceTokenIssuers: map[string]config.TrustIssuerConfig{"local": {Provider: "oidc", IssuerURL: issuer.server.URL, SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}},
		StaticPolicy: config.StaticPolicyConfig{
			DefaultRedirectURIs: []string{"http://localhost/callback"},
			UserGroupMappings:   map[string]map[string][]string{},
			TrustPolicies:       policyMap,
			Clients:             map[string]config.ClientConfig{"client": {TrustBindings: bindings}, "other": {}},
		},
	}
	// Config.Load's trust compiler is intentionally exercised via JSON round trip.
	data, _ := json.Marshal(cfg)
	path := t.TempDir() + "/config.jsonc"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(loaded, nil)
	service.client = issuer.server.Client()
	return service
}

// mustJSON marshals a fixture value.
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestVerifyAndEvaluateProductionPath covers standard claims, signatures, and exactly-one authorization.
func TestVerifyAndEvaluateProductionPath(t *testing.T) {
	issuer := newTLSIssuer(t)
	tests := []struct {
		name        string
		policies    []string
		claims      map[string]any
		options     []any
		want        string
		diagnostics int
	}{
		{"exactly one", []string{"acme/repo", "other/repo"}, nil, nil, "", 2},
		{"zero", []string{"other/a", "other/b"}, nil, nil, "no trust binding matched", 2},
		{"multiple", []string{"acme/repo", "acme/repo"}, nil, nil, "multiple trust bindings matched", 2},
		{"wrong audience", []string{"acme/repo"}, map[string]any{"aud": "other"}, nil, "standard claims are invalid", 0},
		{"multiple audience", []string{"acme/repo"}, map[string]any{"aud": []string{"client", "other"}}, nil, "standard claims are invalid", 0},
		{"azp mismatch", []string{"acme/repo"}, map[string]any{"azp": "other"}, nil, "authorized party is invalid", 0},
		{"empty subject", []string{"acme/repo"}, map[string]any{"sub": ""}, nil, "standard claims are invalid", 0},
		{"expired", []string{"acme/repo"}, map[string]any{"exp": time.Now().Add(-time.Minute)}, nil, "token verification failed", 0},
		{"future nbf", []string{"acme/repo"}, map[string]any{"nbf": time.Now().Add(time.Hour)}, nil, "token verification failed", 0},
		{"stale iat", []string{"acme/repo"}, map[string]any{"iat": time.Now().Add(-time.Hour)}, nil, "standard claims are invalid", 0},
		{"future iat", []string{"acme/repo"}, map[string]any{"iat": time.Now().Add(time.Hour)}, nil, "token verification failed", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := serviceForIssuer(t, issuer, tt.policies...).VerifyAndEvaluate(context.Background(), issuer.sign(tt.claims, tt.options...), "client")
			if tt.want == "" {
				if err != nil || result.Binding == nil {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("result=%+v err=%v, want %q", result, err, tt.want)
			}
			if result != nil && len(result.Diagnostics) != tt.diagnostics {
				t.Fatalf("diagnostics=%+v", result.Diagnostics)
			}
			if err != nil && result != nil && result.Binding != nil {
				t.Fatal("denial retained binding")
			}
		})
	}
}

// TestVerifyAndEvaluateDynamicIssuer exercises database-supplied issuer verification through the production path.
func TestVerifyAndEvaluateDynamicIssuer(t *testing.T) {
	issuer := newTLSIssuer(t)
	service := serviceForIssuer(t, issuer, "acme/repo")
	binding := *service.cfg.StaticPolicy.Clients["client"].TrustBindings[0].Effective
	resolver := &dynamicPolicyResolver{
		issuer:  config.TrustIssuerConfig{Provider: "oidc", IssuerURL: issuer.server.URL, SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)},
		binding: binding,
	}
	service.policyResolver = resolver
	service.dynamicClient = issuer.server.Client()
	result, err := service.VerifyAndEvaluate(context.Background(), issuer.sign(nil), "client")
	if err != nil || result.Binding == nil || result.IssuerID != "dynamic" || resolver.calls != 3 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	resolver.calls = 0
	result, err = service.VerifyAndEvaluate(context.Background(), issuer.sign(nil, otherKey), "client")
	if err == nil || err.Error() != "token verification failed" || result != nil || resolver.calls != 2 {
		t.Fatalf("forged token result=%#v error=%v policy calls=%d, want signature rejection before binding lookup", result, err, resolver.calls)
	}
}

// TestInvalidTokensAvoidPolicyLookup verifies cheap rejection precedes client, issuer, and binding resolution.
func TestInvalidTokensAvoidPolicyLookup(t *testing.T) {
	issuer := newTLSIssuer(t)
	resolver := &dynamicPolicyResolver{}
	service := NewService(&config.Config{}, resolver)
	var deep any = "leaf"
	for range 17 {
		deep = map[string]any{"nested": deep}
	}
	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"missing issuer", map[string]any{"iss": nil}},
		{"missing subject", map[string]any{"sub": nil}},
		{"missing audience", map[string]any{"aud": nil}},
		{"missing expiration", map[string]any{"exp": nil}},
		{"missing issued at", map[string]any{"iat": nil}},
		{"empty subject", map[string]any{"sub": ""}},
		{"wrong audience", map[string]any{"aud": "other"}},
		{"multiple audiences", map[string]any{"aud": []string{"client", "other"}}},
		{"wrong authorized party", map[string]any{"azp": "other"}},
		{"non-string authorized party", map[string]any{"azp": 42}},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Minute)}},
		{"epoch expiration", map[string]any{"exp": time.Unix(0, 0)}},
		{"epoch issued at", map[string]any{"iat": time.Unix(0, 0)}},
		{"future issued at", map[string]any{"iat": time.Now().Add(time.Hour)}},
		{"future not before", map[string]any{"nbf": time.Now().Add(time.Hour)}},
		{"deep claims", map[string]any{"custom": deep}},
		{"long claim", map[string]any{"custom": strings.Repeat("x", 8193)}},
		{"large collection", map[string]any{"custom": make([]any, 257)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.VerifyAndEvaluate(context.Background(), issuer.sign(tt.claims), "client")
			if err == nil || result != nil || resolver.calls != 0 {
				t.Fatalf("result=%#v error=%v policy calls=%d, want rejection before lookup", result, err, resolver.calls)
			}
		})
	}
	for name, raw := range map[string]string{
		"empty":       "",
		"oversized":   strings.Repeat("x", MaxJWTBytes+1),
		"malformed":   "not.a.jwt",
		"missing kid": issuer.sign(nil, ""),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := service.VerifyAndEvaluate(context.Background(), raw, "client")
			if err == nil || result != nil || resolver.calls != 0 {
				t.Fatalf("result=%#v error=%v policy calls=%d, want rejection before lookup", result, err, resolver.calls)
			}
		})
	}
}

// TestVerifyAndEvaluateInfrastructureFailures covers signature, discovery, outage, and key rotation paths.
func TestVerifyAndEvaluateInfrastructureFailures(t *testing.T) {
	issuer := newTLSIssuer(t)
	t.Run("wrong signature", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil, other), "client")
		if err == nil {
			t.Fatal("accepted wrong signature")
		}
	})
	t.Run("wrong algorithm", func(t *testing.T) {
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil, jwa.PS256), "client")
		if err == nil {
			t.Fatal("accepted wrong algorithm")
		}
	})
	t.Run("cross origin redirect", func(t *testing.T) {
		issuer.redirect = "https://example.com/metadata"
		defer func() { issuer.redirect = "" }()
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil), "client")
		if err == nil {
			t.Fatal("followed cross-origin redirect")
		}
	})
	t.Run("outage", func(t *testing.T) {
		issuer.outage = true
		defer func() { issuer.outage = false }()
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil), "client")
		if err == nil {
			t.Fatal("ignored outage")
		}
	})
	t.Run("unknown kid rotation", func(t *testing.T) {
		service := serviceForIssuer(t, issuer, "acme/repo")
		old := issuer.sign(nil)
		if _, err := service.VerifyAndEvaluate(context.Background(), old, "client"); err != nil {
			t.Fatal(err)
		}
		issuer.rotate()
		if _, err := service.VerifyAndEvaluate(context.Background(), issuer.sign(nil), "client"); err != nil {
			t.Fatalf("rotation failed: %v", err)
		}
		if _, err := service.VerifyAndEvaluate(context.Background(), issuer.sign(nil, "never-seen"), "client"); err == nil {
			t.Fatal("unknown kid accepted")
		}
	})
}
