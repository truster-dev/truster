// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/templates"
)

// TestHandleFallbackRedirectsRootAndRendersNotFound verifies root and unmatched-route behavior.
func TestHandleFallbackRedirectsRootAndRendersNotFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "public"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "public", "robots.txt"), []byte("User-agent: *\nDisallow: /\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := templates.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: &config.Config{HomepageURL: "https://app.example.com/sign-in"}, templates: manager}

	root := httptest.NewRecorder()
	server.HandleFallback(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusFound || root.Header().Get("Location") != "https://app.example.com/sign-in" {
		t.Fatalf("root response = %d, location = %q", root.Code, root.Header().Get("Location"))
	}

	asset := httptest.NewRecorder()
	server.HandleFallback(asset, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "Disallow") {
		t.Fatalf("asset response = %d %q", asset.Code, asset.Body.String())
	}

	missing := httptest.NewRecorder()
	server.HandleFallback(missing, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if missing.Code != http.StatusNotFound || missing.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(missing.Body.String(), "Page Not Found") {
		t.Fatalf("missing response = %d %q", missing.Code, missing.Body.String())
	}
}

// TestHandleFallbackRendersRootNotFoundWithoutHomepage verifies the optional redirect remains opt-in.
func TestHandleFallbackRendersRootNotFoundWithoutHomepage(t *testing.T) {
	manager, err := templates.Load("")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: &config.Config{}, templates: manager}
	response := httptest.NewRecorder()
	server.HandleFallback(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "Page Not Found") {
		t.Fatalf("root response = %d %q", response.Code, response.Body.String())
	}
}
