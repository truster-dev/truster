// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/config"
)

// TestDiscoveryRequiresExactIssuerAndSecureJWKS verifies metadata using the production HTTP path.
func TestDiscoveryRequiresExactIssuerAndSecureJWKS(t *testing.T) {
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, serverURL(r)+"jwks")
	}))
	defer server.Close()
	service := &Service{cfg: &config.Config{}, client: server.Client()}
	issuer = server.URL
	if _, err := discovery(context.Background(), service.client, config.TrustIssuerConfig{IssuerURL: issuer}); err != nil {
		t.Fatalf("valid discovery failed: %v", err)
	}
	issuer = server.URL + "/different"
	if _, err := discovery(context.Background(), service.client, config.TrustIssuerConfig{IssuerURL: server.URL}); err == nil {
		t.Fatal("accepted mismatched discovery issuer")
	}
}

// TestVerifyAndEvaluateNilSafety ensures optional trust configuration cannot panic request handling.
func TestVerifyAndEvaluateNilSafety(t *testing.T) {
	var service *Service
	if _, err := service.VerifyAndEvaluate(context.Background(), "token", "client"); err == nil {
		t.Fatal("nil service unexpectedly succeeded")
	}
}

// TestPublicDialContextRejectsPrivateAddresses verifies dynamic issuers cannot reach loopback services.
func TestPublicDialContextRejectsPrivateAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "10.0.0.1:443", "100.64.0.1:443", "[::1]:443", "[fd00::1]:443"} {
		if connection, err := publicDialContext(context.Background(), "tcp", address); err == nil {
			_ = connection.Close()
			t.Fatalf("dialed private issuer address %s", address)
		}
	}
}

// TestDecodePayloadPreservesAdjacentLargeIntegers verifies signed payload numbers are never float-remarshaled.
func TestDecodePayloadPreservesAdjacentLargeIntegers(t *testing.T) {
	left, right := "9007199254740992", "9007199254740993"
	payload := fmt.Sprintf(`{"left":%s,"right":%s}`, left, right)
	claims, err := decodePayload("e30." + rawURL([]byte(payload)) + ".signature")
	if err != nil {
		t.Fatal(err)
	}
	if claims["left"].(json.Number).String() != left || claims["right"].(json.Number).String() != right {
		t.Fatalf("numbers changed: %#v", claims)
	}
}

// TestSelectKeyAcceptsMissingAlgorithmAndRejectsAmbiguity verifies standards-compliant JWK selection.
func TestSelectKeyAcceptsMissingAlgorithmAndRejectsAmbiguity(t *testing.T) {
	key := testPublicJWK(t, "key")
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "key", "RS256"); err != nil {
		t.Fatalf("missing alg rejected: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS512); err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "key", "RS256"); err == nil {
		t.Fatal("wrong JWK alg accepted")
	}
	_ = key.Remove(jwk.AlgorithmKey)
	if err := set.AddKey(testPublicJWK(t, "key")); err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "key", "RS256"); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	if _, err := selectKey(set, "unknown", "RS256"); err == nil {
		t.Fatal("unknown kid accepted")
	}
}

// TestIssuerCacheCoalescesAndRefreshes verifies bounded requests, rotation, and random-kid cooldown.
func TestIssuerCacheCoalescesAndRefreshes(t *testing.T) {
	var issuer string
	var mu sync.Mutex
	requests := 0
	current := testPublicJWK(t, "one")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		key := current
		mu.Unlock()
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks")
			return
		}
		data, _ := json.Marshal(map[string]any{"keys": []jwk.Key{key}})
		_, _ = w.Write(data)
	}))
	defer server.Close()
	issuer = server.URL
	service := &Service{cfg: &config.Config{}, client: server.Client(), cache: make(map[string]cachedIssuer)}
	configuration := authpolicy.ResolvedTrustIssuer{Config: config.TrustIssuerConfig{IssuerURL: issuer}}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := service.loadIssuer(context.Background(), configuration, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	count := requests
	current = testPublicJWK(t, "two")
	mu.Unlock()
	if count != 2 {
		t.Fatalf("concurrent initial load made %d requests, want 2", count)
	}
	set, err := service.loadIssuer(context.Background(), configuration, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "two", "RS256"); err != nil {
		t.Fatalf("rotation not loaded: %v", err)
	}
	for range 10 {
		_, _ = service.loadIssuer(context.Background(), configuration, true)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 4 {
		t.Fatalf("refresh cooldown made %d requests, want 4", requests)
	}
}

// TestIssuerCacheCoolsDownFailedRefreshes verifies outages cannot amplify random-key requests.
func TestIssuerCacheCoolsDownFailedRefreshes(t *testing.T) {
	var issuer string
	var mu sync.Mutex
	requests := 0
	outage := false
	key := testPublicJWK(t, "one")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		unavailable := outage
		mu.Unlock()
		if unavailable {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks")
			return
		}
		data, _ := json.Marshal(map[string]any{"keys": []jwk.Key{key}})
		_, _ = w.Write(data)
	}))
	defer server.Close()
	issuer = server.URL
	service := &Service{cfg: &config.Config{}, client: server.Client(), cache: make(map[string]cachedIssuer)}
	configuration := authpolicy.ResolvedTrustIssuer{Config: config.TrustIssuerConfig{IssuerURL: issuer}}
	if _, err := service.loadIssuer(context.Background(), configuration, false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	outage = true
	mu.Unlock()
	if _, err := service.loadIssuer(context.Background(), configuration, true); err == nil {
		t.Fatal("forced refresh unexpectedly succeeded during outage")
	}
	for range 10 {
		_, _ = service.loadIssuer(context.Background(), configuration, true)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 3 {
		t.Fatalf("failed refresh cooldown made %d requests, want 3", requests)
	}
}

// TestIssuerCacheBoundAndSourceIsolation verifies eviction and the dynamic network boundary on cache hits.
func TestIssuerCacheBoundAndSourceIsolation(t *testing.T) {
	issuer := newTLSIssuer(t)
	service := NewService(&config.Config{}, nil)
	service.client = issuer.server.Client()
	keys := jwk.NewSet()
	now := time.Now()
	for i := range maxCachedIssuers {
		service.cache[fmt.Sprintf("static:https://issuer-%d.example", i)] = cachedIssuer{keys: keys, expires: now.Add(time.Duration(i) * time.Minute)}
	}
	resolved := authpolicy.ResolvedTrustIssuer{Config: config.TrustIssuerConfig{IssuerURL: issuer.server.URL}}
	if _, err := service.loadIssuer(context.Background(), resolved, false); err != nil {
		t.Fatal(err)
	}
	if len(service.cache) != maxCachedIssuers {
		t.Fatalf("cache entries=%d, want %d", len(service.cache), maxCachedIssuers)
	}
	if _, exists := service.cache["static:https://issuer-0.example"]; exists {
		t.Fatal("oldest cache entry was not evicted")
	}
	resolved.Dynamic = true
	if _, err := service.loadIssuer(context.Background(), resolved, false); err == nil || !strings.Contains(err.Error(), "no reachable public address") {
		t.Fatalf("dynamic issuer did not enforce its network boundary: %v", err)
	}
}

// TestDynamicIssuerRejectsPrivateJWKS verifies public discovery cannot redirect key retrieval into private infrastructure.
func TestDynamicIssuerRejectsPrivateJWKS(t *testing.T) {
	var requests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprintf(w, `{"issuer":"https://example.com","jwks_uri":%q}`, server.URL+"/jwks")
	}))
	defer server.Close()
	service := NewService(&config.Config{}, nil)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		// Route only the public discovery fixture locally; JWKS still uses the
		// production dialer and must reject the advertised loopback address.
		if address == "example.com:443" {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		return publicDialContext(ctx, network, address)
	}
	defer transport.CloseIdleConnections()
	service.dynamicClient.Transport = transport
	resolved := authpolicy.ResolvedTrustIssuer{Dynamic: true, Config: config.TrustIssuerConfig{IssuerURL: "https://example.com"}}
	if _, err := service.loadIssuer(context.Background(), resolved, false); err == nil || !strings.Contains(err.Error(), "JWKS unavailable") || !strings.Contains(err.Error(), "no reachable public address") {
		t.Fatalf("private JWKS error=%v, want network rejection after discovery", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("issuer requests=%d, want discovery only", requests.Load())
	}
}

// TestAllowedDynamicIssuerIP verifies direct private destinations are blocked without blanket IPv6 restrictions.
func TestAllowedDynamicIssuerIP(t *testing.T) {
	for _, address := range []string{
		"8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111",
		"100.63.255.255", "100.128.0.0", // Both sides of shared IPv4 space.
		"192.0.0.9", "192.0.0.10", "2001:3::1", // Reachable special-purpose allocations.
		"64:ff9b::808:808", "2002:0808:0808::", // Public NAT64 and 6to4 destinations.
	} {
		if !allowedDynamicIssuerIP(netip.MustParseAddr(address)) {
			t.Errorf("allowed destination rejected: %s", address)
		}
	}
	for _, address := range []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1",
		"100.64.0.0", "100.127.255.255", "::ffff:100.64.0.1",
		"169.254.169.254", "224.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"fe80::1", "fd00::1", "ff02::1",
	} {
		if allowedDynamicIssuerIP(netip.MustParseAddr(address)) {
			t.Errorf("blocked destination accepted: %s", address)
		}
	}
	if allowedDynamicIssuerIP(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
}

// testPublicJWK creates an RSA public JWK without an alg member.
func testPublicJWK(t *testing.T, kid string) jwk.Key {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	return key
}

// rawURL returns unpadded base64url.
func rawURL(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

// serverURL reconstructs the TLS test server origin.
func serverURL(r *http.Request) string { return "https://" + r.Host + "/" }
