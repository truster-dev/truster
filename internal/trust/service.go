// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/truster-dev/truster/v3/internal/authpolicy"
	"github.com/truster-dev/truster/v3/internal/config"
	"golang.org/x/sync/singleflight"
)

const (
	// MaxJWTBytes is the shared maximum compact external JWT size.
	MaxJWTBytes      = 64 << 10
	cacheTTL         = 5 * time.Minute
	refreshWait      = 30 * time.Second
	maxCachedIssuers = 1024
)

// sharedIPv4Space is carrier-grade NAT space, which netip.IsPrivate does not cover.
var sharedIPv4Space = netip.MustParsePrefix("100.64.0.0/10")

// policyResolver defines the client and trust decisions consumed during token verification.
type policyResolver interface {
	ResolveClient(context.Context, string, bool) (authpolicy.ResolvedClient, error)
	ResolveTrustIssuer(context.Context, authpolicy.ResolvedClient, string) (authpolicy.ResolvedTrustIssuer, error)
	ResolveTrustBindings(context.Context, authpolicy.ResolvedClient, authpolicy.ResolvedTrustIssuer) ([]config.EffectiveTrustBinding, error)
}

// Result contains verified provenance and the exactly matched binding.
type Result struct {
	IssuerID, Issuer, UpstreamSubject string
	Claims                            map[string]any
	Binding                           *config.EffectiveTrustBinding
	Diagnostics                       []Diagnostic
}

// Diagnostic records a bounded, token-free binding evaluation result.
type Diagnostic struct {
	BindingID string
	Match     bool
	Reason    string
}

// Service performs external verification and policy evaluation.
type Service struct {
	cfg            *config.Config
	client         *http.Client
	dynamicClient  *http.Client
	mu             sync.Mutex
	cache          map[string]cachedIssuer
	loads          singleflight.Group
	policyResolver policyResolver
}

// cachedIssuer holds validated metadata and keys for a bounded interval.
type cachedIssuer struct {
	document    discoveryDocument
	keys        jwk.Set
	expires     time.Time
	lastRefresh time.Time
}

// NewService constructs a verifier with bounded HTTP behavior.
func NewService(cfg *config.Config, resolver policyResolver) *Service {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 2 || req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("cross-origin redirect rejected")
		}
		return nil
	}
	if resolver == nil {
		resolver = authpolicy.NewResolver(cfg, nil)
	}
	dynamicTransport := transport.Clone()
	dynamicTransport.Proxy = nil
	dynamicTransport.DialContext = publicDialContext
	dynamicTransport.DialTLSContext = nil
	dynamicClient := &http.Client{Timeout: client.Timeout, Transport: dynamicTransport, CheckRedirect: client.CheckRedirect}
	return &Service{cfg: cfg, client: client, dynamicClient: dynamicClient, cache: make(map[string]cachedIssuer), policyResolver: resolver}
}

// VerifyAndEvaluate runs the complete production verification and exactly-one evaluator.
func (s *Service) VerifyAndEvaluate(ctx context.Context, raw, clientID string) (*Result, error) {
	if s == nil || s.cfg == nil || s.client == nil {
		return nil, fmt.Errorf("trust service is unavailable")
	}
	if len(raw) == 0 || len(raw) > MaxJWTBytes {
		return nil, fmt.Errorf("token size is invalid")
	}
	alg, kid, err := tokenHeaders(raw)
	if err != nil || kid == "" {
		return nil, fmt.Errorf("unacceptable token header")
	}
	unverified, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("malformed token")
	}
	issuerURL := unverified.Issuer()
	if issuerURL == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	// Reject obviously invalid tokens before any policy or network lookup.
	// Passing these checks does not authenticate the token; repeat them after
	// verifying the signature over the same original bytes.
	if err := validateStandardClaims(unverified, clientID); err != nil {
		return nil, err
	}
	claims, err := decodePayload(raw)
	if err != nil {
		return nil, fmt.Errorf("decoded claims exceed safe limits")
	}
	if err := boundClaims(claims, 0); err != nil {
		return nil, err
	}
	resolved, err := s.policyResolver.ResolveClient(ctx, clientID, true)
	if err != nil {
		if authpolicy.IsIndeterminate(err) {
			return nil, err
		}
		return nil, fmt.Errorf("unknown client")
	}
	resolvedIssuer, err := s.policyResolver.ResolveTrustIssuer(ctx, resolved, issuerURL)
	if err != nil {
		if authpolicy.IsIndeterminate(err) {
			return nil, err
		}
		return nil, fmt.Errorf("untrusted issuer")
	}
	issuerName, issuer := resolvedIssuer.ID, resolvedIssuer.Config
	if !contains(issuer.SigningAlgs, alg) {
		return nil, fmt.Errorf("unacceptable token header")
	}
	set, err := s.loadIssuer(ctx, resolvedIssuer, false)
	if err != nil {
		return nil, err
	}
	key, keyErr := selectKey(set, kid, alg)
	if keyErr != nil {
		set, err = s.loadIssuer(ctx, resolvedIssuer, true)
		if err == nil {
			key, keyErr = selectKey(set, kid, alg)
		}
	}
	if keyErr != nil {
		return nil, fmt.Errorf("token verification failed")
	}
	verified, err := jwt.Parse([]byte(raw), jwt.WithKey(jwa.SignatureAlgorithm(alg), key), jwt.WithValidate(false))
	if err != nil || verified.Issuer() != issuer.IssuerURL {
		return nil, fmt.Errorf("token verification failed")
	}
	if err := validateStandardClaims(verified, clientID); err != nil {
		return nil, err
	}
	if time.Since(verified.IssuedAt()) > issuer.MaxTokenAge.Duration() {
		return nil, fmt.Errorf("standard claims are invalid")
	}
	result := &Result{IssuerID: issuerName, Issuer: issuerURL, UpstreamSubject: verified.Subject(), Claims: claims}
	bindings, resolveErr := s.policyResolver.ResolveTrustBindings(ctx, resolved, resolvedIssuer)
	if resolveErr != nil {
		return result, resolveErr
	}
	matches := 0
	for i := range bindings {
		binding := &bindings[i]
		validationErr := binding.Schema.Validate(claims)
		diagnostic := Diagnostic{BindingID: binding.ID, Match: validationErr == nil}
		if validationErr != nil {
			diagnostic.Reason = "claims did not satisfy policy"
		}
		result.Diagnostics = append(result.Diagnostics, diagnostic)
		if validationErr == nil {
			matches++
			result.Binding = binding
		}
	}
	if matches != 1 {
		result.Binding = nil
	}
	if matches == 0 {
		return result, fmt.Errorf("no trust binding matched")
	}
	if matches > 1 {
		return result, fmt.Errorf("multiple trust bindings matched")
	}
	return result, nil
}

// validateStandardClaims rejects invalid issuer-independent claims before and after signature verification.
func validateStandardClaims(token jwt.Token, clientID string) error {
	if err := jwt.Validate(token, jwt.WithRequiredClaim(jwt.SubjectKey), jwt.WithRequiredClaim(jwt.AudienceKey), jwt.WithRequiredClaim(jwt.ExpirationKey), jwt.WithRequiredClaim(jwt.IssuedAtKey)); err != nil {
		return fmt.Errorf("token verification failed")
	}
	// jwx skips time validation for zero and epoch-zero dates, even when the
	// claim is present. Neither is a usable expiration or issued-at value.
	if token.Subject() == "" || len(token.Audience()) != 1 || token.Audience()[0] != clientID || token.Expiration().IsZero() || token.Expiration().Unix() == 0 || token.IssuedAt().IsZero() || token.IssuedAt().Unix() == 0 {
		return fmt.Errorf("standard claims are invalid")
	}
	if azp, exists := token.Get("azp"); exists {
		value, ok := azp.(string)
		if !ok || value != clientID {
			return fmt.Errorf("authorized party is invalid")
		}
	}
	return nil
}

// decodePayload decodes the original signed bytes while preserving JSON numbers exactly.
func decodePayload(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid compact JWS")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(data) > MaxJWTBytes {
		return nil, fmt.Errorf("invalid payload")
	}
	claims := make(map[string]any)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// loadIssuer returns cached validated discovery and JWKS, coalescing upstream loads.
func (s *Service) loadIssuer(ctx context.Context, resolved authpolicy.ResolvedTrustIssuer, force bool) (jwk.Set, error) {
	issuer := resolved.Config
	cacheKey := "static:" + issuer.IssuerURL
	client := s.client
	if resolved.Dynamic {
		cacheKey = "dynamic:" + issuer.IssuerURL
		client = s.dynamicClient
	}
	if client == nil {
		return nil, fmt.Errorf("issuer HTTP client is unavailable")
	}
	now := time.Now()
	s.mu.Lock()
	if s.cache == nil {
		s.cache = make(map[string]cachedIssuer)
	}
	cached := s.cache[cacheKey]
	if cached.keys != nil && ((!force && now.Before(cached.expires)) || (force && now.Sub(cached.lastRefresh) < refreshWait)) {
		s.mu.Unlock()
		return cached.keys, nil
	}
	s.mu.Unlock()
	value, err, _ := s.loads.Do(cacheKey, func() (any, error) {
		s.mu.Lock()
		current := s.cache[cacheKey]
		if current.keys != nil && ((!force && time.Now().Before(current.expires)) || (force && time.Since(current.lastRefresh) < refreshWait)) {
			s.mu.Unlock()
			return current.keys, nil
		}
		if force {
			current.lastRefresh = time.Now()
			if current.keys != nil {
				s.cache[cacheKey] = current
			}
		}
		s.mu.Unlock()
		doc, loadErr := discovery(ctx, client, issuer)
		if loadErr != nil {
			return nil, loadErr
		}
		keys, loadErr := fetchJWKS(ctx, client, doc.JWKSURI)
		if loadErr != nil {
			return nil, loadErr
		}
		s.mu.Lock()
		if _, exists := s.cache[cacheKey]; !exists && len(s.cache) >= maxCachedIssuers {
			var oldestKey string
			var oldest time.Time
			for key, entry := range s.cache {
				if oldestKey == "" || entry.expires.Before(oldest) {
					oldestKey, oldest = key, entry.expires
				}
			}
			delete(s.cache, oldestKey)
		}
		refreshed := current.lastRefresh
		s.cache[cacheKey] = cachedIssuer{document: doc, keys: keys, expires: time.Now().Add(cacheTTL), lastRefresh: refreshed}
		s.mu.Unlock()
		return keys, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(jwk.Set), nil
}

// selectKey requires exactly one compatible key ID while allowing an omitted JWK alg.
func selectKey(set jwk.Set, kid, alg string) (jwk.Key, error) {
	var selected jwk.Key
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok || key.KeyID() != kid {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("duplicate kid")
		}
		if key.Algorithm() != nil && key.Algorithm().String() != "" && key.Algorithm().String() != alg {
			return nil, fmt.Errorf("JWK algorithm mismatch")
		}
		selected = key
	}
	if selected == nil {
		return nil, fmt.Errorf("unknown kid")
	}
	return selected, nil
}

// discoveryDocument contains the OIDC metadata required for token verification.
type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discovery fetches and validates bounded OIDC metadata.
func discovery(ctx context.Context, client *http.Client, issuer config.TrustIssuerConfig) (discoveryDocument, error) {
	var doc discoveryDocument
	if err := getJSON(ctx, client, strings.TrimSuffix(issuer.IssuerURL, "/")+"/.well-known/openid-configuration", 32<<10, &doc); err != nil {
		return doc, fmt.Errorf("discovery unavailable: %w", err)
	}
	if doc.Issuer != issuer.IssuerURL {
		return doc, fmt.Errorf("discovery issuer mismatch")
	}
	u, err := url.Parse(doc.JWKSURI)
	if err != nil || u.Scheme != "https" {
		base, _ := url.Parse(issuer.IssuerURL)
		if base == nil || base.Scheme != "http" || !isLocal(base.Hostname()) || u == nil || u.Scheme != "http" || !isLocal(u.Hostname()) {
			return doc, fmt.Errorf("jwks_uri must use HTTPS")
		}
	}
	return doc, nil
}

// fetchJWKS obtains a bounded key set from validated metadata.
func fetchJWKS(ctx context.Context, client *http.Client, uri string) (jwk.Set, error) {
	var raw json.RawMessage
	if err := getJSON(ctx, client, uri, 128<<10, &raw); err != nil {
		return nil, fmt.Errorf("JWKS unavailable: %w", err)
	}
	set, err := jwk.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS")
	}
	return set, nil
}

// getJSON performs one size-limited JSON GET.
func getJSON(ctx context.Context, client *http.Client, uri string, limit int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return fmt.Errorf("response too large")
	}
	if err = json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid JSON")
	}
	return nil
}

// tokenHeaders extracts protected algorithm and key ID without trusting claims.
func tokenHeaders(raw string) (string, string, error) {
	message, err := jws.Parse([]byte(raw))
	if err != nil || len(message.Signatures()) != 1 {
		return "", "", fmt.Errorf("invalid JWS")
	}
	headers := message.Signatures()[0].ProtectedHeaders()
	return headers.Algorithm().String(), headers.KeyID(), nil
}

// contains reports exact string membership.
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// publicDialContext filters resolved destinations and dials their IPs without a second DNS lookup.
func publicDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer address")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer host: %w", err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok || !allowedDynamicIssuerIP(ip) {
			continue
		}
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return connection, nil
		}
	}
	return nil, fmt.Errorf("issuer host has no reachable public address")
}

// allowedDynamicIssuerIP rejects direct local, private, and shared-network destinations.
// Deployment egress controls must enforce restrictions involving routing or address translation.
func allowedDynamicIssuerIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !sharedIPv4Space.Contains(ip)
}

// isLocal reports whether HTTP development is permitted for a host.
func isLocal(host string) bool { return host == "localhost" || host == "127.0.0.1" || host == "::1" }

// boundClaims limits token value depth, lengths, and collection sizes before policy lookup.
func boundClaims(value any, depth int) error {
	if depth > 16 {
		return fmt.Errorf("claims exceed safe depth")
	}
	switch x := value.(type) {
	case map[string]any:
		if len(x) > 128 {
			return fmt.Errorf("too many claims")
		}
		for key, v := range x {
			if len(key) > 256 {
				return fmt.Errorf("claim name too long")
			}
			if err := boundClaims(v, depth+1); err != nil {
				return err
			}
		}
	case []any:
		if len(x) > 256 {
			return fmt.Errorf("claim collection too large")
		}
		for _, v := range x {
			if err := boundClaims(v, depth+1); err != nil {
				return err
			}
		}
	case string:
		if len(x) > 8192 {
			return fmt.Errorf("claim string too long")
		}
	}
	return nil
}
