// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestSecurityHeadersPreventFraming verifies the central middleware protects every response.
func TestSecurityHeadersPreventFraming(t *testing.T) {
	server := &Server{}
	handler := server.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if got := response.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Fatalf("Content-Security-Policy = %q", got)
	}
	if got := response.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
	if got := response.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
}

// TestParseBrowserFormRejectsUnsafeRequests verifies form type, size, and field uniqueness checks.
func TestParseBrowserFormRejectsUnsafeRequests(t *testing.T) {
	server := &Server{}
	tests := []struct {
		name, contentType, body string
	}{
		{name: "wrong content type", contentType: "text/plain", body: "state=one"},
		{name: "duplicate field", contentType: "application/x-www-form-urlencoded", body: "state=one&state=two"},
		{name: "oversized", contentType: "application/x-www-form-urlencoded", body: "state=" + strings.Repeat("a", maxBrowserFormBytes)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			if server.parseBrowserForm(response, request, "state") || response.Code != http.StatusBadRequest {
				t.Fatalf("accepted unsafe form with status %d", response.Code)
			}
		})
	}
}

// TestPublicEndpointRateLimitsRunBeforeHandlers verifies floods do no handler work.
func TestPublicEndpointRateLimitsRunBeforeHandlers(t *testing.T) {
	server := &Server{publicEndpointLimits: map[string]*rate.Limiter{}}
	for _, path := range []string{"/par", "/token", "/revoke"} {
		t.Run(path, func(t *testing.T) {
			server.publicEndpointLimits[path] = rate.NewLimiter(0, publicEndpointBurst)
			called := 0
			handler := server.LimitPublicEndpoints(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called++
				w.WriteHeader(http.StatusNoContent)
			}))
			for range publicEndpointBurst {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
				if response.Code != http.StatusNoContent {
					t.Fatalf("allowed status = %d", response.Code)
				}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
			if response.Code != http.StatusTooManyRequests || called != publicEndpointBurst || response.Header().Get("Retry-After") != "1" {
				t.Fatalf("limited status=%d called=%d retry=%q", response.Code, called, response.Header().Get("Retry-After"))
			}
		})
	}
}

// TestEndpointLimiterRefillsAtConfiguredRate verifies deterministic token-bucket refill.
func TestEndpointLimiterRefillsAtConfiguredRate(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := rate.NewLimiter(publicEndpointRate, 1)
	if !limiter.AllowN(now, 1) {
		t.Fatal("initial token was not available")
	}
	if !limiter.AllowN(now.Add(time.Second/100), 1) {
		t.Fatal("one token was not restored at the configured rate")
	}
	if limiter.AllowN(now.Add(time.Second/100), 1) {
		t.Fatal("refill admitted more than the configured rate")
	}
}
