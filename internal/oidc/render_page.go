// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"net/http"

	"github.com/truster-dev/truster/v2/internal/templates"
)

// pageData returns the common, non-sensitive context exposed to browser templates.
func (s *Server) pageData(r *http.Request) templates.PageData {
	data := templates.PageData{
		Request: templates.RequestData{Method: r.Method, Host: r.Host, Path: r.URL.Path},
	}
	if s.config != nil {
		data.IssuerURL = s.config.IssuerURL
		data.HomepageURL = s.config.HomepageURL
	}
	return data
}

// renderBrowserPage buffers a browser page so render failures can return a clean error page.
func (s *Server) renderBrowserPage(w http.ResponseWriter, r *http.Request, status int, name string, data any, failureReason browserFailureReason) {
	var body bytes.Buffer
	if err := s.templates.RenderPage(&body, name, data); err != nil {
		s.renderBrowserError(w, r, http.StatusInternalServerError, failureReason)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}
