// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"mime"
	"net/http"

	"golang.org/x/time/rate"
)

const (
	publicEndpointRate  = rate.Limit(100)
	publicEndpointBurst = 200
	maxBrowserFormBytes = 32 << 10
)

// SecurityHeaders prevents framing and browser-state leakage to another origin.
func (s *Server) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// parseBrowserForm bounds and validates a URL-encoded browser form and rejects duplicate named fields.
func (s *Server) parseBrowserForm(w http.ResponseWriter, r *http.Request, fields ...string) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		s.renderBrowserError(w, r, http.StatusBadRequest, failureInvalidFormContentType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBrowserFormBytes)
	if err = r.ParseForm(); err != nil {
		s.renderBrowserError(w, r, http.StatusBadRequest, failureInvalidFormBody)
		return false
	}
	for _, field := range fields {
		if len(r.PostForm[field]) > 1 {
			s.renderBrowserError(w, r, http.StatusBadRequest, failureDuplicateFormField)
			return false
		}
	}
	return true
}

// LimitPublicEndpoints rate-limits expensive public endpoints before handler work.
func (s *Server) LimitPublicEndpoints(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := s.publicEndpointLimits[r.URL.Path]
		if limiter != nil && !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			writeOAuthJSON(w, http.StatusTooManyRequests, "temporarily_unavailable")
			return
		}
		next.ServeHTTP(w, r)
	})
}
