// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/truster-dev/truster/v3/internal/config"
)

// trustCommandFixture provides check trust with a configuration, TLS issuer, and signed token.
type trustCommandFixture struct {
	t          *testing.T
	server     *httptest.Server
	key        *rsa.PrivateKey
	configPath string
	token      string
}

// newTrustCommandFixture creates a complete configuration with the requested binding policies.
func newTrustCommandFixture(t *testing.T, repositories ...string) *trustCommandFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &trustCommandFixture{t: t, key: key}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)

	bindings := make([]config.TrustBindingConfig, len(repositories))
	policies := make(map[string]config.TrustPolicyConfig, len(repositories))
	for i, repository := range repositories {
		name := "policy" + string(rune('A'+i))
		policies[name] = config.TrustPolicyConfig{
			Issuer:  "local",
			Subject: "trusted:builder",
			Groups:  []string{"builders"},
			Claims:  map[string]json.RawMessage{"repository": json.RawMessage(`{"const":` + quoted(t, repository) + `}`)},
		}
		bindings[i] = config.TrustBindingConfig{ID: "binding-" + name, TrustPolicy: name}
	}
	cfg := config.Config{
		IssuerURL: "https://downstream.example", HTTPListenAddr: ":8080",
		Secrets:             config.SecretsConfig{Provider: "env", SigningKeyName: "SIGNING_KEY"},
		UserLoginConnectors: map[string]config.ConnectorConfig{"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "GOOGLE_CREDENTIALS", Scopes: []string{"openid", "email"}}},
		ServiceTokenIssuers: map[string]config.TrustIssuerConfig{"local": {Provider: "oidc", IssuerURL: fixture.server.URL, SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}},
		StaticPolicy: config.StaticPolicyConfig{
			DefaultRedirectURIs: []string{"http://localhost/callback"},
			UserGroupMappings:   map[string]map[string][]string{},
			Clients:             map[string]config.ClientConfig{"client": {TrustBindings: bindings}},
			TrustPolicies:       policies,
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fixture.configPath = filepath.Join(t.TempDir(), "config.jsonc")
	if err = os.WriteFile(fixture.configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = config.Load(fixture.configPath); err != nil {
		t.Fatalf("fixture config is invalid: %v", err)
	}
	fixture.token = fixture.sign()
	return fixture
}

// serveHTTP serves exact OIDC discovery and JWKS responses.
func (f *trustCommandFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL, "jwks_uri": f.server.URL + "/jwks"})
	case "/jwks":
		public, err := jwk.FromRaw(&f.key.PublicKey)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = public.Set(jwk.KeyIDKey, "test-key")
		_ = public.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk.Key{public}})
	default:
		http.NotFound(w, r)
	}
}

// sign creates a valid external JWT for the fixture issuer and client.
func (f *trustCommandFixture) sign() string {
	now := time.Now().UTC()
	token := jwt.New()
	for name, value := range map[string]any{"iss": f.server.URL, "sub": "external-user", "aud": "client", "iat": now, "exp": now.Add(time.Hour), "repository": "acme/repo"} {
		if err := token.Set(name, value); err != nil {
			f.t.Fatal(err)
		}
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, "test-key")
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, f.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(signed)
}

// quoted returns a JSON string literal.
func quoted(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// executeTrustCheck invokes the production command with the local TLS transport.
func executeTrustCheck(t *testing.T, fixture *trustCommandFixture, tokenFile string, stdin string) (string, error) {
	t.Helper()
	original := http.DefaultTransport
	http.DefaultTransport = fixture.server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	var output bytes.Buffer
	configPath := fixture.configPath
	command := newCheckTrustCmd(&configPath)
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetIn(strings.NewReader(stdin))
	command.SetArgs([]string{"--client-id", "client", "--token-file", tokenFile})
	err := command.Execute()
	return output.String(), err
}

// TestCheckTrustCommandTokenInputs verifies file and stdin use the same production path.
func TestCheckTrustCommandTokenInputs(t *testing.T) {
	fixture := newTrustCommandFixture(t, "acme/repo", "other/repo")
	tokenPath := filepath.Join(t.TempDir(), "token.jwt")
	if err := os.WriteFile(tokenPath, []byte(fixture.token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fromFile, fileErr := executeTrustCheck(t, fixture, tokenPath, "")
	fromStdin, stdinErr := executeTrustCheck(t, fixture, "-", fixture.token+"\n")
	if fileErr != nil || stdinErr != nil {
		t.Fatalf("file error=%v, stdin error=%v", fileErr, stdinErr)
	}
	if fromFile != fromStdin {
		t.Fatalf("reports differ:\nfile: %q\nstdin: %q", fromFile, fromStdin)
	}
	for _, want := range []string{"issuer: " + fixture.server.URL, "standard claims: verified", "binding binding-policyA: match", "binding binding-policyB: no match", "subject: trusted:builder", "groups: builders"} {
		if !strings.Contains(fromFile, want) {
			t.Errorf("report missing %q: %s", want, fromFile)
		}
	}
	if strings.Contains(fromFile, fixture.token) {
		t.Fatal("report exposed raw token")
	}
}

// TestCheckTrustCommandDeniedDiagnostics verifies zero and ambiguous results remain non-effective.
func TestCheckTrustCommandDeniedDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name, want string
		repos      []string
	}{
		{name: "zero", repos: []string{"other/a", "other/b"}, want: "no trust binding matched"},
		{name: "ambiguous", repos: []string{"acme/repo", "acme/repo"}, want: "multiple trust bindings matched"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTrustCommandFixture(t, test.repos...)
			output, err := executeTrustCheck(t, fixture, "-", fixture.token)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
			for _, binding := range []string{"binding-policyA", "binding-policyB"} {
				if !strings.Contains(output, "binding "+binding+":") {
					t.Errorf("missing diagnostic for %s: %s", binding, output)
				}
			}
			if strings.Contains(output, "subject:") || strings.Contains(output, "groups:") || strings.Contains(output, fixture.token) || strings.Contains(err.Error(), fixture.token) {
				t.Fatalf("denial exposed effective identity or token: output=%q error=%v", output, err)
			}
		})
	}
}

// TestCheckTrustCommandOpenErrorRedaction verifies attacker-controlled paths and JWT material are absent.
func TestCheckTrustCommandOpenErrorRedaction(t *testing.T) {
	fixture := newTrustCommandFixture(t, "acme/repo")
	supplied := filepath.Join(t.TempDir(), "missing-"+fixture.token)
	output, err := executeTrustCheck(t, fixture, supplied, "")
	if err == nil || !strings.Contains(err.Error(), "open token file: unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := output + err.Error()
	if strings.Contains(combined, supplied) || strings.Contains(combined, fixture.token) {
		t.Fatalf("open error exposed supplied material: %q", combined)
	}
}
