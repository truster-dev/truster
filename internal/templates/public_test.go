// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestHandlePublicServesFiles verifies public files, headers, methods, and missing paths.
func TestHandlePublicServesFiles(t *testing.T) {
	dir := t.TempDir()
	publicDir := filepath.Join(dir, "public", "images")
	if err := os.MkdirAll(publicDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pages"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pages", "error.html"), []byte(`{{define "content"}}<h1>{{.Title}}</h1><p>{{.Request.Method}} {{.Request.Host}} {{.Request.Path}} {{.IssuerURL}} {{.HomepageURL}}</p>{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	content := []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
	if err := os.WriteFile(filepath.Join(publicDir, "logo.svg"), content, 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := httptest.NewRecorder()
		manager.HandlePublic(response, httptest.NewRequest(method, "/images/logo.svg", nil), PageData{})
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/svg+xml" || response.Header().Get("Content-Length") != strconv.Itoa(len(content)) {
			t.Fatalf("%s response = %d, headers = %v", method, response.Code, response.Header())
		}
		if response.Header().Get("Cache-Control") != "no-cache" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s cache or security headers missing: %v", method, response.Header())
		}
		if method == http.MethodGet && response.Body.String() != string(content) {
			t.Fatalf("GET body = %q", response.Body.String())
		}
		if method == http.MethodHead && response.Body.Len() != 0 {
			t.Fatalf("HEAD body = %q", response.Body.String())
		}
	}

	methodResponse := httptest.NewRecorder()
	manager.HandlePublic(methodResponse, httptest.NewRequest(http.MethodPost, "/images/logo.svg", nil), PageData{})
	if methodResponse.Code != http.StatusMethodNotAllowed || methodResponse.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST response = %d, headers = %v", methodResponse.Code, methodResponse.Header())
	}
	missingResponse := httptest.NewRecorder()
	missingRequest := httptest.NewRequest(http.MethodGet, "/images/missing.svg", nil)
	missingRequest.Host = "auth.example.com"
	manager.HandlePublic(missingResponse, missingRequest, PageData{IssuerURL: "https://auth.example.com", HomepageURL: "https://app.example.com"})
	if missingResponse.Code != http.StatusNotFound || missingResponse.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(missingResponse.Body.String(), "Page Not Found") || !strings.Contains(missingResponse.Body.String(), "GET auth.example.com /images/missing.svg https://auth.example.com https://app.example.com") {
		t.Fatalf("missing response = %d %q", missingResponse.Code, missingResponse.Body.String())
	}
}

// TestHandlePublicLeavesRegisteredRoutesInControl verifies protocol routes take precedence over public files.
func TestHandlePublicLeavesRegisteredRoutesInControl(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "public"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "public", "authorize"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("oidc")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		manager.HandlePublic(w, r, PageData{})
	})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if response.Body.String() != "oidc" {
		t.Fatalf("route body = %q", response.Body.String())
	}
}

// TestLoadPublicAcceptsMissingDirectoryAndRejectsSymlinks verifies startup validation.
func TestLoadPublicAcceptsMissingDirectoryAndRejectsSymlinks(t *testing.T) {
	if _, err := Load(t.TempDir()); err != nil {
		t.Fatalf("missing public directory: %v", err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "public"), 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "public", "linked.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("public symlink accepted")
	}
}
