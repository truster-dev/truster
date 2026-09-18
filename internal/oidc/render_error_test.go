// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truster-dev/truster/v2/internal/templates"
)

// TestBrowserFormFailureRendersHTMLWithoutLoggingRequestData verifies friendly output and privacy-safe diagnostics.
func TestBrowserFormFailureRendersHTMLWithoutLoggingRequestData(t *testing.T) {
	manager, err := templates.Load("")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server := &Server{templates: manager, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	request := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("state=secret-state&state=user@example.com"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "secret-user-agent")
	request.RemoteAddr = "192.0.2.40:1234"
	response := httptest.NewRecorder()

	if server.parseBrowserForm(response, request, "state") {
		t.Fatal("duplicate state was accepted")
	}
	if response.Code != http.StatusBadRequest || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(response.Body.String(), "Unable to continue") {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	output := logs.String()
	for _, required := range []string{`"reason":"duplicate_form_field"`, `"status":400`} {
		if !strings.Contains(output, required) {
			t.Errorf("log missing %s: %s", required, output)
		}
	}
	for _, private := range []string{"secret-state", "user@example.com", "secret-user-agent", "192.0.2.40"} {
		if strings.Contains(output, private) {
			t.Errorf("log leaked %q: %s", private, output)
		}
	}
}
