// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"net/http"

	"github.com/truster-dev/truster/v2/internal/templates"
)

// renderErrorPage renders a browser error with the configured error template.
func (s *Server) renderErrorPage(w http.ResponseWriter, status int, title, message string) {
	if s.templates == nil {
		http.Error(w, message, status)
		return
	}
	var body bytes.Buffer
	if err := s.templates.RenderPage(&body, "error", templates.ErrorData{Title: title, Message: message}); err != nil {
		if s.logger != nil {
			s.logger.Error("render error page", "error", err)
		}
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}
