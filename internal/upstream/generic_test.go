// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/truster-dev/truster/v3/internal/config"
	"golang.org/x/oauth2"
)

// genericConnectorServer serves a test userinfo response.
func genericConnectorServer(t *testing.T, includeSubject bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := map[string]any{"email": "User@Example.com", "email_verified": true}
		if includeSubject {
			response["sub"] = "stable-subject"
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
}

// testGenericConnector creates a connector targeting a test server.
func testGenericConnector(serverURL string) *GenericConnector {
	return NewGenericConnector(config.ConnectorConfig{Generic: &config.GenericConfig{
		AuthorizationURL: serverURL + "/auth",
		TokenURL:         serverURL + "/token",
		UserinfoURL:      serverURL,
		SubjectField:     "sub",
	}}, "https://auth.example.com/callback/generic", "client", "secret")
}

// TestGenericConnectorGetsStableIdentity verifies subject and email extraction.
func TestGenericConnectorGetsStableIdentity(t *testing.T) {
	server := genericConnectorServer(t, true)
	defer server.Close()
	identity, err := testGenericConnector(server.URL).GetIdentity(context.Background(), &oauth2.Token{AccessToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "stable-subject" || len(identity.Emails) != 1 || identity.Emails[0].Address != "User@Example.com" || !identity.Emails[0].Verified {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

// TestGenericConnectorRequiresSubject verifies missing subjects are rejected.
func TestGenericConnectorRequiresSubject(t *testing.T) {
	server := genericConnectorServer(t, false)
	defer server.Close()
	if _, err := testGenericConnector(server.URL).GetIdentity(context.Background(), &oauth2.Token{AccessToken: "token"}); err == nil {
		t.Fatal("identity without subject accepted")
	}
}
