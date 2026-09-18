// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"net/http"
)

// renderBrowserPage buffers a browser page so render failures can return a clean error page.
func (s *Server) renderBrowserPage(w http.ResponseWriter, status int, name string, data any, failureReason browserFailureReason) {
	var body bytes.Buffer
	if err := s.templates.RenderPage(&body, name, data); err != nil {
		s.renderBrowserError(w, http.StatusInternalServerError, failureReason)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}
