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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/config"
	"golang.org/x/sync/singleflight"
)

const (
	// MaxJWTBytes is the shared maximum compact external JWT size.
	MaxJWTBytes = 64 << 10
	cacheTTL    = 5 * time.Minute
	refreshWait = 30 * time.Second
)

// policyResolver defines the client and trust decisions consumed during token verification.
type policyResolver interface {
	ResolveClient(context.Context, string, bool) (authpolicy.ResolvedClient, error)
	ResolveTrust(context.Context, authpolicy.ResolvedClient, string) ([]config.EffectiveTrustBinding, error)
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
	return &Service{cfg: cfg, client: client, cache: make(map[string]cachedIssuer), policyResolver: resolver}
}

// VerifyAndEvaluate runs the complete production verification and exactly-one evaluator.
func (s *Service) VerifyAndEvaluate(ctx context.Context, raw, clientID string) (*Result, error) {
	if s == nil || s.cfg == nil || s.client == nil {
		return nil, fmt.Errorf("trust service is unavailable")
	}
	if len(raw) == 0 || len(raw) > MaxJWTBytes {
		return nil, fmt.Errorf("token size is invalid")
	}
	resolved, err := s.policyResolver.ResolveClient(ctx, clientID, true)
	if err != nil {
		if authpolicy.IsIndeterminate(err) {
			return nil, err
		}
		return nil, fmt.Errorf("unknown client")
	}
	unverified, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("malformed token")
	}
	issuerURL := unverified.Issuer()
	if issuerURL == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	issuerName, issuer, ok := s.findIssuer(issuerURL)
	if !ok {
		return nil, fmt.Errorf("untrusted issuer")
	}
	alg, kid, err := tokenHeaders(raw)
	if err != nil || !contains(issuer.SigningAlgs, alg) || kid == "" {
		return nil, fmt.Errorf("unacceptable token header")
	}
	set, err := s.loadIssuer(ctx, issuer, false)
	if err != nil {
		return nil, err
	}
	key, keyErr := selectKey(set, kid, alg)
	if keyErr != nil {
		set, err = s.loadIssuer(ctx, issuer, true)
		if err == nil {
			key, keyErr = selectKey(set, kid, alg)
		}
	}
	if keyErr != nil {
		return nil, fmt.Errorf("token verification failed")
	}
	verified, err := jwt.Parse([]byte(raw), jwt.WithKey(jwa.SignatureAlgorithm(alg), key), jwt.WithValidate(true), jwt.WithIssuer(issuer.IssuerURL), jwt.WithRequiredClaim(jwt.SubjectKey), jwt.WithRequiredClaim(jwt.AudienceKey), jwt.WithRequiredClaim(jwt.ExpirationKey), jwt.WithRequiredClaim(jwt.IssuedAtKey))
	if err != nil {
		return nil, fmt.Errorf("token verification failed")
	}
	if verified.Subject() == "" || len(verified.Audience()) != 1 || verified.Audience()[0] != clientID || verified.IssuedAt().IsZero() || time.Since(verified.IssuedAt()) > issuer.MaxTokenAge.Duration() || verified.IssuedAt().After(time.Now().Add(time.Minute)) {
		return nil, fmt.Errorf("standard claims are invalid")
	}
	if azp, exists := verified.Get("azp"); exists {
		value, ok := azp.(string)
		if !ok || value != clientID {
			return nil, fmt.Errorf("authorized party is invalid")
		}
	}
	claims, err := decodePayload(raw)
	if err != nil {
		return nil, fmt.Errorf("decoded claims exceed safe limits")
	}
	if err = boundClaims(claims, 0); err != nil {
		return nil, err
	}
	result := &Result{IssuerID: issuerName, Issuer: issuerURL, UpstreamSubject: verified.Subject(), Claims: claims}
	bindings, resolveErr := s.policyResolver.ResolveTrust(ctx, resolved, issuerName)
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
func (s *Service) loadIssuer(ctx context.Context, issuer config.TrustIssuerConfig, force bool) (jwk.Set, error) {
	now := time.Now()
	s.mu.Lock()
	if s.cache == nil {
		s.cache = make(map[string]cachedIssuer)
	}
	cached := s.cache[issuer.IssuerURL]
	if cached.keys != nil && ((!force && now.Before(cached.expires)) || (force && now.Sub(cached.lastRefresh) < refreshWait)) {
		s.mu.Unlock()
		return cached.keys, nil
	}
	s.mu.Unlock()
	value, err, _ := s.loads.Do(issuer.IssuerURL, func() (any, error) {
		s.mu.Lock()
		current := s.cache[issuer.IssuerURL]
		if current.keys != nil && ((!force && time.Now().Before(current.expires)) || (force && time.Since(current.lastRefresh) < refreshWait)) {
			s.mu.Unlock()
			return current.keys, nil
		}
		if force {
			current.lastRefresh = time.Now()
			s.cache[issuer.IssuerURL] = current
		}
		s.mu.Unlock()
		doc, loadErr := s.discovery(ctx, issuer)
		if loadErr != nil {
			return nil, loadErr
		}
		keys, loadErr := s.fetchJWKS(ctx, doc.JWKSURI, issuer.IssuerURL)
		if loadErr != nil {
			return nil, loadErr
		}
		s.mu.Lock()
		refreshed := current.lastRefresh
		s.cache[issuer.IssuerURL] = cachedIssuer{document: doc, keys: keys, expires: time.Now().Add(cacheTTL), lastRefresh: refreshed}
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

type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// findIssuer selects a configured issuer by exact URL.
func (s *Service) findIssuer(value string) (string, config.TrustIssuerConfig, bool) {
	for name, issuer := range s.cfg.ServiceTokenIssuers {
		if issuer.IssuerURL == value {
			return name, issuer, true
		}
	}
	return "", config.TrustIssuerConfig{}, false
}

// discovery fetches and validates bounded OIDC metadata.
func (s *Service) discovery(ctx context.Context, issuer config.TrustIssuerConfig) (discoveryDocument, error) {
	var doc discoveryDocument
	if err := s.getJSON(ctx, strings.TrimSuffix(issuer.IssuerURL, "/")+"/.well-known/openid-configuration", 32<<10, &doc); err != nil {
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
func (s *Service) fetchJWKS(ctx context.Context, uri, issuer string) (jwk.Set, error) {
	var raw json.RawMessage
	if err := s.getJSON(ctx, uri, 128<<10, &raw); err != nil {
		return nil, fmt.Errorf("JWKS unavailable: %w", err)
	}
	set, err := jwk.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS")
	}
	return set, nil
}

// getJSON performs one size-limited JSON GET.
func (s *Service) getJSON(ctx context.Context, uri string, limit int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
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

// isLocal reports whether HTTP development is permitted for a host.
func isLocal(host string) bool { return host == "localhost" || host == "127.0.0.1" || host == "::1" }

// boundClaims limits verified value depth, lengths, and collection sizes.
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
