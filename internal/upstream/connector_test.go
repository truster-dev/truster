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
	"time"

	"github.com/truster-dev/truster/v3/internal/config"
	"golang.org/x/oauth2"
)

// TestNormalizeCredentialPersistsExtraExpiry verifies provider extras become stable metadata.
func TestNormalizeCredentialPersistsExtraExpiry(t *testing.T) {
	now := time.Now().UTC()
	token := (&oauth2.Token{AccessToken: "access", RefreshToken: "refresh"}).WithExtra(map[string]any{"expires_in": "60", "refresh_token_expires_in": float64(120)})
	credential := NormalizeCredential(token, now, false)
	if !credential.AccessExpiry.Equal(now.Add(time.Minute)) || !credential.RefreshExpiry.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("normalized expiry = %v, %v", credential.AccessExpiry, credential.RefreshExpiry)
	}
}

// TestGoogleIdentityRequiresConfiguredHostedDomain verifies refresh-time hd revalidation.
func TestGoogleIdentityRequiresConfiguredHostedDomain(t *testing.T) {
	connector := NewGoogleConnector(config.ConnectorConfig{Google: &config.GoogleConfig{HostedDomain: "example.com"}}, "https://issuer.example/callback/google", "client", "secret")
	for _, test := range []struct {
		name, hostedDomain string
		wantError          bool
	}{
		{name: "matching", hostedDomain: "example.com"},
		{name: "mismatch", hostedDomain: "other.example", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				body := `{"sub":"subject","email":"user@example.com","email_verified":true,"hd":"` + test.hostedDomain + `"}`
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			_, err := connector.GetIdentity(ctx, &oauth2.Token{AccessToken: "access"})
			if (err != nil) != test.wantError {
				t.Fatalf("GetIdentity() error = %v, wantError=%v", err, test.wantError)
			}
		})
	}
}
