// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
)

// HandleFallback redirects the issuer root, serves public files, and renders branded not-found pages.
func (s *Server) HandleFallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && s.config.HomepageURL != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		http.Redirect(w, r, s.config.HomepageURL, http.StatusFound)
		return
	}
	s.templates.HandlePublic(w, r, s.pageData(r))
}
