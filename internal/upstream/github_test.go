// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/truster-dev/truster/v3/internal/config"
	"golang.org/x/oauth2"
)

// roundTripFunc adapts a function into an HTTP transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip invokes the adapted transport function.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// TestGitHubConnectorReturnsUsableEmails verifies GitHub email assertions are
// never preselected and GitHub noreply addresses are excluded.
func TestGitHubConnectorReturnsUsableEmails(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"id":123}`
		if request.URL.Path == "/user/emails" {
			body = `[{"email":"primary@example.com","primary":true,"verified":false},{"email":"123+user@users.noreply.github.com","primary":false,"verified":true},{"email":"verified@example.com","primary":false,"verified":true}]`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	connector := NewGitHubConnector(config.ConnectorConfig{Type: "github"}, "https://auth.example.com/callback/github", "client", "secret")
	identity, err := connector.GetIdentity(ctx, &oauth2.Token{AccessToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "123" || len(identity.Emails) != 2 {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if identity.Emails[0].Address != "primary@example.com" || !identity.Emails[0].Primary || identity.Emails[0].Verified {
		t.Fatalf("unexpected primary email: %#v", identity.Emails[0])
	}
	if identity.Emails[1].Address != "verified@example.com" || identity.Emails[1].Primary || !identity.Emails[1].Verified {
		t.Fatalf("unexpected verified email: %#v", identity.Emails[1])
	}
}

// TestGitHubConnectorRejectsOnlyNoreplyEmails verifies that a GitHub account
// without a deliverable email cannot authenticate.
func TestGitHubConnectorRejectsOnlyNoreplyEmails(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"id":123}`
		if request.URL.Path == "/user/emails" {
			body = `[{"email":"user@users.noreply.github.com","primary":true,"verified":true}]`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	connector := NewGitHubConnector(config.ConnectorConfig{Type: "github"}, "https://auth.example.com/callback/github", "client", "secret")
	if _, err := connector.GetIdentity(ctx, &oauth2.Token{AccessToken: "token"}); err == nil || !strings.Contains(err.Error(), "no email found") {
		t.Fatalf("GetIdentity() error = %v, want no email found", err)
	}
}
