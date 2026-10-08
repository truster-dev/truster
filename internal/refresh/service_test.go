// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package refresh

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/statedb"
	"github.com/truster-dev/truster/v3/internal/tokens"
	"github.com/truster-dev/truster/v3/internal/upstream"
	"golang.org/x/oauth2"
)

// testConnector is a controllable renewable upstream for refresh tests.
type testConnector struct {
	identity       upstream.Identity
	identityErrors []error
	refreshed      *upstream.Credential
	refreshError   error
	identityCalls  int
	refreshCalls   int
	exitOnIdentity bool
}

// fakePolicyResolver is a controllable policy resolver for persistence tests.
type fakePolicyResolver struct {
	client      authpolicy.ResolvedClient
	userResults []authpolicy.ResolvedUser
	userErrors  []error
	userCalls   int
	freshCalls  []bool
}

// ResolveClient returns the configured dynamic client.
func (f *fakePolicyResolver) ResolveClient(_ context.Context, _ string, fresh bool) (authpolicy.ResolvedClient, error) {
	f.freshCalls = append(f.freshCalls, fresh)
	return f.client, nil
}

// ResolveUser returns the next configured policy decision.
func (f *fakePolicyResolver) ResolveUser(context.Context, authpolicy.ResolvedClient, string) (authpolicy.ResolvedUser, error) {
	index := f.userCalls
	f.userCalls++
	if index < len(f.userErrors) && f.userErrors[index] != nil {
		return authpolicy.ResolvedUser{}, f.userErrors[index]
	}
	return f.userResults[index], nil
}

// AuthCodeURL satisfies upstream.Connector.
func (*testConnector) AuthCodeURL(string, ...oauth2.AuthCodeOption) string { return "" }

// Exchange satisfies upstream.Connector.
func (*testConnector) Exchange(context.Context, string) (*upstream.Credential, error) {
	return nil, errors.New("unexpected exchange")
}

// Refresh returns the configured replacement credential.
func (c *testConnector) Refresh(context.Context, *upstream.Credential) (*upstream.Credential, error) {
	c.refreshCalls++
	return c.refreshed, c.refreshError
}

// GetIdentity returns the next configured identity result.
func (c *testConnector) GetIdentity(_ context.Context, token *oauth2.Token) (upstream.Identity, error) {
	if c.exitOnIdentity {
		if c.refreshCalls != 1 || token.AccessToken != "new-access" {
			return upstream.Identity{}, errors.New("identity called before refresh completed")
		}
		os.Exit(0)
	}
	index := c.identityCalls
	c.identityCalls++
	if index < len(c.identityErrors) && c.identityErrors[index] != nil {
		return upstream.Identity{}, c.identityErrors[index]
	}
	return c.identity, nil
}

// TestProviderResponseCrashProcess exits after provider rotation returns but before commit.
func TestProviderResponseCrashProcess(t *testing.T) {
	path := os.Getenv("TRUSTER_PROVIDER_RESPONSE_CRASH_DB")
	if path == "" {
		t.Skip("subprocess helper")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := tokens.NewSigner(&tokens.SigningKey{Algorithm: jwa.EdDSA, PrivateKey: privateKey, PublicKey: publicKey}, "kid", "https://issuer.example", time.Hour)
	requireUserGroupsFromPolicy := false
	cfg := &config.Config{
		AccessTokenTTL:      config.Duration(15 * time.Minute),
		IDTokenTTL:          config.Duration(10 * time.Minute),
		Email:               &config.EmailConfig{VerificationMode: "provider"},
		UserLoginConnectors: map[string]config.ConnectorConfig{"provider": {Type: "generic"}},
		StaticPolicy: config.StaticPolicyConfig{
			RequireUserGroupsFromPolicy: &requireUserGroupsFromPolicy,
			Clients:                     map[string]config.ClientConfig{"client": {RefreshTokens: config.RefreshTokenConfig{Enabled: true}}},
		},
	}
	connector := &testConnector{refreshed: &upstream.Credential{AccessToken: "new-access", RefreshToken: "new-refresh", AccessExpiry: time.Now().Add(time.Hour)}, exitOnIdentity: true}
	service := NewService(cfg, store, signer, map[string]upstream.Connector{"provider": connector}, logger, authpolicy.NewResolver(cfg, nil))
	if _, exchangeErr := service.Exchange(context.Background(), Request{Token: os.Getenv("TRUSTER_PROVIDER_RESPONSE_CRASH_TOKEN"), ClientID: "client"}); exchangeErr != nil {
		t.Fatal(exchangeErr)
	}
	t.Fatal("exchange reached the final commit")
}

// TestRestartAfterProviderResponseFencesGrant verifies the production ordering around connector.Refresh.
func TestRestartAfterProviderResponseFencesGrant(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	path := t.TempDir() + "/restart.db"
	store, err := statedb.NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	material, err := statedb.GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := json.Marshal(&upstream.Credential{AccessToken: "old-access", RefreshToken: "old-refresh", AccessExpiry: now.Add(-time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := statedb.EncryptCredential(material.Secret, "provider-response", "client", "provider", credential)
	if err != nil {
		t.Fatal(err)
	}
	grant := statedb.RefreshGrant{SID: "provider-response", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "provider", UpstreamSubject: "subject", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err = store.CreateRefreshGrant(grant, material, nonce, ciphertext, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestProviderResponseCrashProcess$")
	command.Env = append(os.Environ(), "TRUSTER_PROVIDER_RESPONSE_CRASH_DB="+path, "TRUSTER_PROVIDER_RESPONSE_CRASH_TOKEN="+material.Token)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("provider-response crash helper: %v\n%s", runErr, output)
	}
	store, err = statedb.NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = store.ClaimRefresh(material, "client", time.Now().Add(time.Minute), time.Minute); !errors.Is(err, statedb.ErrCredentialIndeterminate) {
		t.Fatalf("claim after provider-response crash = %v", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = statedb.NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, _, err = store.PrepareRefresh(material, "client", time.Now()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("indeterminate grant was not durably revoked: %v", err)
	}
}

// testFixture owns concrete refresh dependencies.
type testFixture struct {
	service *Service
	store   *statedb.Store
	signer  *tokens.Signer
	cfg     *config.Config
}

// newTestFixture creates a refresh service with secure production implementations.
func newTestFixture(t *testing.T, connectors map[string]upstream.Connector) *testFixture {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := tokens.NewSigner(&tokens.SigningKey{Algorithm: jwa.EdDSA, PrivateKey: privateKey, PublicKey: publicKey}, "kid", "https://issuer.example", time.Hour)
	requireUserGroupsFromPolicy := false
	cfg := &config.Config{
		AccessTokenTTL: config.Duration(15 * time.Minute),
		IDTokenTTL:     config.Duration(10 * time.Minute),
		Email:          &config.EmailConfig{VerificationMode: "provider"},
		UserLoginConnectors: map[string]config.ConnectorConfig{
			"email":    {Type: "email"},
			"provider": {Type: "generic"},
		},
		StaticPolicy: config.StaticPolicyConfig{
			RequireUserGroupsFromPolicy: &requireUserGroupsFromPolicy,
			Clients: map[string]config.ClientConfig{
				"client": {RefreshTokens: config.RefreshTokenConfig{Enabled: true, AllowOfflineAccess: true}},
			},
		},
	}
	return &testFixture{service: NewService(cfg, store, signer, connectors, logger, authpolicy.NewResolver(cfg, nil)), store: store, signer: signer, cfg: cfg}
}

// createGrant creates one refresh family and encrypts an optional upstream credential.
func (f *testFixture) createGrant(t *testing.T, sid, connectorID string, credential *upstream.Credential) statedb.RefreshMaterial {
	t.Helper()
	now := time.Now().UTC()
	material, err := statedb.GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	grant := statedb.RefreshGrant{SID: sid, ClientID: "client", Email: "user@example.com", Scopes: "openid email profile", ConnectorID: connectorID, UpstreamSubject: "user@example.com", Mode: "session", AuthTime: now.Add(-time.Hour), IdleTTL: time.Hour, AbsoluteExpiry: now.Add(4 * time.Hour)}
	var nonce, ciphertext []byte
	if credential != nil {
		grant.UpstreamSubject = "subject"
		encoded, encodeErr := json.Marshal(credential)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		nonce, ciphertext, err = statedb.EncryptCredential(material.Secret, sid, "client", connectorID, encoded)
		if err != nil {
			t.Fatal(err)
		}
		grant.CredentialNonce, grant.CredentialCiphertext = nonce, ciphertext
	}
	if err = f.store.CreateRefreshGrant(grant, material, nonce, ciphertext, now); err != nil {
		t.Fatal(err)
	}
	return material
}

// TestDirectExchangeRotatesAndNarrows verifies the local refresh happy path and stable identity claims.
func TestDirectExchangeRotatesAndNarrows(t *testing.T) {
	fixture := newTestFixture(t, nil)
	current := fixture.createGrant(t, "direct-sid", "email", nil)
	result, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client", Scope: "openid email"})
	if exchangeErr != nil {
		t.Fatal(exchangeErr)
	}
	if result.RefreshToken == current.Token || result.Scope != "openid email" || result.SID != "direct-sid" {
		t.Fatalf("unexpected result: %#v", result)
	}
	idToken, err := fixture.signer.VerifyToken(result.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if sid, _ := idToken.Get("sid"); sid != "direct-sid" {
		t.Fatalf("sid = %v", sid)
	}
	if _, _, err = fixture.store.PrepareRefresh(current, "client", time.Now().UTC()); !errors.Is(err, statedb.ErrRefreshReplay) {
		t.Fatalf("old token = %v, want replay", err)
	}
}

// TestRejectedRefreshDoesNotConsumeGrant verifies scope and client failures cannot damage a valid grant.
func TestRejectedRefreshDoesNotConsumeGrant(t *testing.T) {
	fixture := newTestFixture(t, nil)
	current := fixture.createGrant(t, "bound-sid", "email", nil)
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client", Scope: "openid admin"}); exchangeErr == nil || exchangeErr.Code != InvalidScope {
		t.Fatalf("superset error = %v", exchangeErr)
	}
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "other"}); exchangeErr == nil || exchangeErr.Code != InvalidGrant {
		t.Fatalf("wrong-client error = %v", exchangeErr)
	}
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr != nil {
		t.Fatalf("valid retry failed: %v", exchangeErr)
	}
}

// TestReplayRevokesReplacement verifies family compromise invalidates the winning token immediately.
func TestReplayRevokesReplacement(t *testing.T) {
	fixture := newTestFixture(t, nil)
	current := fixture.createGrant(t, "replay-sid", "email", nil)
	result, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"})
	if exchangeErr != nil {
		t.Fatal(exchangeErr)
	}
	if _, exchangeErr = fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr == nil || exchangeErr.Code != InvalidGrant {
		t.Fatalf("replay error = %v", exchangeErr)
	}
	if _, exchangeErr = fixture.service.Exchange(context.Background(), Request{Token: result.RefreshToken, ClientID: "client"}); exchangeErr == nil || exchangeErr.Code != InvalidGrant {
		t.Fatalf("replacement after replay = %v", exchangeErr)
	}
}

// TestCurrentPolicyRevokesGrant verifies disabled refresh policy is applied at use time.
func TestCurrentPolicyRevokesGrant(t *testing.T) {
	fixture := newTestFixture(t, nil)
	current := fixture.createGrant(t, "policy-sid", "email", nil)
	client := fixture.cfg.StaticPolicy.Clients["client"]
	client.RefreshTokens.Enabled = false
	fixture.cfg.StaticPolicy.Clients["client"] = client
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr == nil || exchangeErr.Code != InvalidGrant {
		t.Fatalf("policy error = %v", exchangeErr)
	}
	if _, _, err := fixture.store.PrepareRefresh(current, "client", time.Now().UTC()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("grant remained active: %v", err)
	}
}

// TestDynamicPolicyPersistence verifies temporary decisions preserve a grant and denial revokes it.
func TestDynamicPolicyPersistence(t *testing.T) {
	t.Run("indeterminate then current groups", func(t *testing.T) {
		fixture := newTestFixture(t, nil)
		client := fixture.cfg.StaticPolicy.Clients["client"]
		fake := &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: client}, userErrors: []error{&authpolicy.IndeterminateError{Err: context.DeadlineExceeded}, nil}, userResults: []authpolicy.ResolvedUser{{}, {Groups: []string{"updated"}}}}
		fixture.service.policyResolver = fake
		current := fixture.createGrant(t, "dynamic-retry", "email", nil)
		if _, failure := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); failure == nil || failure.Code != Temporary {
			t.Fatalf("temporary decision=%#v", failure)
		}
		if _, _, err := fixture.store.PrepareRefresh(current, "client", time.Now().UTC()); err != nil {
			t.Fatalf("temporary decision damaged grant: %v", err)
		}
		result, failure := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"})
		if failure != nil {
			t.Fatal(failure)
		}
		verified, err := fixture.signer.VerifyToken(result.IDToken)
		if err != nil {
			t.Fatal(err)
		}
		groups, _ := verified.Get("groups")
		encoded, _ := json.Marshal(groups)
		if string(encoded) != `["updated"]` {
			t.Fatalf("groups=%s", encoded)
		}
		if len(fake.freshCalls) != 2 || !fake.freshCalls[0] || !fake.freshCalls[1] {
			t.Fatalf("client freshness checks=%v", fake.freshCalls)
		}
	})
	t.Run("definitive denial revokes", func(t *testing.T) {
		fixture := newTestFixture(t, nil)
		client := fixture.cfg.StaticPolicy.Clients["client"]
		fixture.service.policyResolver = &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: client}, userErrors: []error{authpolicy.ErrDenied}}
		current := fixture.createGrant(t, "dynamic-denial", "email", nil)
		if _, failure := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); failure == nil || failure.Code != InvalidGrant {
			t.Fatalf("denial=%#v", failure)
		}
		if _, failure := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); failure == nil || failure.Code != InvalidGrant {
			t.Fatalf("retry after revocation=%#v", failure)
		}
		if fake, ok := fixture.service.policyResolver.(*fakePolicyResolver); !ok || fake.userCalls != 1 {
			t.Fatalf("policy resolver was called after revocation: %#v", fixture.service.policyResolver)
		}
	})
}

// TestConnectorExchangeRevalidatesAndPersists verifies current identity evidence and credential re-encryption.
func TestConnectorExchangeRevalidatesAndPersists(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{identity: upstream.Identity{Subject: "subject", Emails: []upstream.Email{{Address: "user@example.com", Verified: false}, {Address: "USER@example.com", Verified: true}}}}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "connector-sid", "provider", &upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: now.Add(time.Hour)})
	result, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"})
	if exchangeErr != nil {
		t.Fatal(exchangeErr)
	}
	if connector.identityCalls != 1 || connector.refreshCalls != 0 {
		t.Fatalf("identity calls=%d refresh calls=%d", connector.identityCalls, connector.refreshCalls)
	}
	idToken, err := fixture.signer.VerifyToken(result.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if verified, _ := idToken.Get("email_verified"); verified != true {
		t.Fatalf("email_verified = %v", verified)
	}
	replacement, err := statedb.ParseRefreshToken(result.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := fixture.store.PrepareRefresh(replacement, "client", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = statedb.DecryptCredential(replacement.Secret, grant.SID, grant.ClientID, grant.ConnectorID, grant.CredentialNonce, grant.CredentialCiphertext); err != nil {
		t.Fatalf("replacement credential: %v", err)
	}
}

// TestConnectorRefreshPersistsRotatedCredential verifies provider rotation is committed under the replacement secret.
func TestConnectorRefreshPersistsRotatedCredential(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{
		identity:  upstream.Identity{Subject: "subject", Emails: []upstream.Email{{Address: "user@example.com", Verified: true}}},
		refreshed: &upstream.Credential{AccessToken: "new-access", RefreshToken: "new-refresh", AccessExpiry: now.Add(time.Hour)},
	}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "rotated-sid", "provider", &upstream.Credential{AccessToken: "old-access", RefreshToken: "old-refresh", AccessExpiry: now.Add(time.Second)})
	result, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"})
	if exchangeErr != nil {
		t.Fatal(exchangeErr)
	}
	if connector.refreshCalls != 1 {
		t.Fatalf("refresh calls = %d", connector.refreshCalls)
	}
	replacement, _ := statedb.ParseRefreshToken(result.RefreshToken)
	grant, _, err := fixture.store.PrepareRefresh(replacement, "client", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := statedb.DecryptCredential(replacement.Secret, grant.SID, grant.ClientID, grant.ConnectorID, grant.CredentialNonce, grant.CredentialCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	var credential upstream.Credential
	if err = json.Unmarshal(plain, &credential); err != nil || credential.RefreshToken != "new-refresh" {
		t.Fatalf("stored credential = %#v, err=%v", credential, err)
	}
}

// TestTemporaryIdentityFailureReleasesClaim verifies safe pre-rotation failures remain retryable.
func TestTemporaryIdentityFailureReleasesClaim(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{
		identity:       upstream.Identity{Subject: "subject", Emails: []upstream.Email{{Address: "user@example.com", Verified: true}}},
		identityErrors: []error{&upstream.ConnectorError{Kind: upstream.ErrorTemporary, Operation: "userinfo"}},
	}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "temporary-sid", "provider", &upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: now.Add(time.Hour)})
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr == nil || exchangeErr.Code != Temporary {
		t.Fatalf("temporary error = %v", exchangeErr)
	}
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr != nil {
		t.Fatalf("full retry failed: %v", exchangeErr)
	}
}

// TestPostRotationIdentityFailureFencesFamily verifies stale rotated credentials can never be retried.
func TestPostRotationIdentityFailureFencesFamily(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{
		identityErrors: []error{&upstream.ConnectorError{Kind: upstream.ErrorTemporary, Operation: "userinfo"}},
		refreshed:      &upstream.Credential{AccessToken: "new-access", RefreshToken: "new-refresh", AccessExpiry: now.Add(time.Hour)},
	}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "fenced-sid", "provider", &upstream.Credential{AccessToken: "old-access", RefreshToken: "old-refresh", AccessExpiry: now.Add(time.Second)})
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr == nil || exchangeErr.Code != InvalidGrant {
		t.Fatalf("post-rotation error = %v", exchangeErr)
	}
	if _, _, err := fixture.store.PrepareRefresh(current, "client", time.Now().UTC()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("stale family remained usable: %v", err)
	}
}

// TestConcurrentConnectorRefreshReturnsRetryGuidance verifies an active claim is non-destructive.
func TestConcurrentConnectorRefreshReturnsRetryGuidance(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{identity: upstream.Identity{Subject: "subject", Emails: []upstream.Email{{Address: "user@example.com", Verified: true}}}}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "busy-sid", "provider", &upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: now.Add(time.Hour)})
	if _, _, _, err := fixture.store.ClaimRefresh(current, "client", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr == nil || exchangeErr.Code != Temporary || exchangeErr.RetryAfter == "" {
		t.Fatalf("busy error = %#v", exchangeErr)
	}
	if _, _, err := fixture.store.PrepareRefresh(current, "client", time.Now().UTC()); err != nil {
		t.Fatalf("busy request revoked grant: %v", err)
	}
}

// TestConcurrentConnectorRefreshWaitsForReleasedClaim verifies brief contention can recover.
func TestConcurrentConnectorRefreshWaitsForReleasedClaim(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{identity: upstream.Identity{Subject: "subject", Emails: []upstream.Email{{Address: "user@example.com", Verified: true}}}}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "released-sid", "provider", &upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: now.Add(time.Hour)})
	_, claim, _, err := fixture.store.ClaimRefresh(current, "client", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		released <- fixture.store.ReleaseRefreshClaim("released-sid", claim)
	}()
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr != nil {
		t.Fatalf("exchange after release = %#v", exchangeErr)
	}
	if err = <-released; err != nil {
		t.Fatalf("release claim: %v", err)
	}
}

// TestUnauthorizedIdentityRefreshesOnce verifies the one-refresh, one-retry contract.
func TestUnauthorizedIdentityRefreshesOnce(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{
		identity:       upstream.Identity{Subject: "subject", Emails: []upstream.Email{{Address: "user@example.com", Verified: true}}},
		identityErrors: []error{&upstream.ConnectorError{Kind: upstream.ErrorUnauthorized, Operation: "userinfo"}},
		refreshed:      &upstream.Credential{AccessToken: "new-access", RefreshToken: "refresh", AccessExpiry: now.Add(time.Hour)},
	}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "retry-sid", "provider", &upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: now.Add(time.Hour)})
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr != nil {
		t.Fatalf("exchange = %#v", exchangeErr)
	}
	if connector.refreshCalls != 1 || connector.identityCalls != 2 {
		t.Fatalf("refresh calls = %d, identity calls = %d", connector.refreshCalls, connector.identityCalls)
	}
}

// TestIdentityMismatchRevokesGrant verifies immutable subject and email binding.
func TestIdentityMismatchRevokesGrant(t *testing.T) {
	now := time.Now().UTC()
	connector := &testConnector{identity: upstream.Identity{Subject: "other-subject", Emails: []upstream.Email{{Address: "user@example.com", Verified: true}}}}
	fixture := newTestFixture(t, map[string]upstream.Connector{"provider": connector})
	current := fixture.createGrant(t, "mismatch-sid", "provider", &upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: now.Add(time.Hour)})
	if _, exchangeErr := fixture.service.Exchange(context.Background(), Request{Token: current.Token, ClientID: "client"}); exchangeErr == nil || exchangeErr.Code != InvalidGrant {
		t.Fatalf("mismatch error = %v", exchangeErr)
	}
	if _, _, err := fixture.store.PrepareRefresh(current, "client", time.Now().UTC()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("mismatched family remained usable: %v", err)
	}
}
