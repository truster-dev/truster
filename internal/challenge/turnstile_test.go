// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package challenge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc adapts a function into an HTTP transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip invokes the adapted transport function.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

// TestTurnstileFailsClosed verifies rejected and missing challenges fail.
func TestTurnstileFailsClosed(t *testing.T) {
	verifier := Turnstile{Secret: "secret", Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		if string(body) != "remoteip=203.0.113.1&response=response&secret=secret" {
			t.Fatalf("unexpected request body: %s", body)
		}
		responseBody := fmt.Sprintf("{%q:%t,%q:[%q]}", "success", false, "error-codes", "invalid-input-response")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(responseBody))}, nil
	})}}
	if err := verifier.Verify(context.Background(), "response", "203.0.113.1"); err == nil || err.Error() != "challenge rejected: invalid-input-response" {
		t.Fatalf("unexpected rejected challenge error: %v", err)
	}
	if err := verifier.Verify(context.Background(), "", ""); err == nil {
		t.Fatal("missing Turnstile response accepted")
	}
}
