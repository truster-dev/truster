// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/truster-dev/truster/v2/internal/config"
)

// TestValidateDPoPBinding covers the only supported binding profiles.
func TestValidateDPoPBinding(t *testing.T) {
	tests := []struct {
		mode, jkt string
		want      bool
	}{
		{"disabled", "", true},
		{"disabled", "jkt", false},
		{"required", "", false},
		{"required", "jkt", true},
	}
	for _, test := range tests {
		if got := validateDPoPBinding(config.ClientConfig{DPoP: config.DPoPConfig{Mode: test.mode}}, test.jkt); got != test.want {
			t.Fatalf("validateDPoPBinding(%q, %q) = %v, want %v", test.mode, test.jkt, got, test.want)
		}
	}
}

// TestStateSatisfiesClientPolicyRequiresPARProvenance verifies policy changes reject direct flows.
func TestStateSatisfiesClientPolicyRequiresPARProvenance(t *testing.T) {
	client := config.ClientConfig{RedirectURIs: []string{"https://client.example/callback"}, DPoP: config.DPoPConfig{Mode: "disabled"}, RequirePAR: true}
	state := OAuthState{RedirectURI: "https://client.example/callback"}
	if stateSatisfiesClientPolicy(&state, client) {
		t.Fatal("direct authorization state satisfied require_par policy")
	}
	state.PushedAuthorization = true
	if !stateSatisfiesClientPolicy(&state, client) {
		t.Fatal("pushed authorization state did not satisfy require_par policy")
	}
}

// TestLogDPoPReplayIncludesSafeIdentifiers verifies replay logs retain protocol identifiers only.
func TestLogDPoPReplayIncludesSafeIdentifiers(t *testing.T) {
	var logs bytes.Buffer
	server := &Server{logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	server.logDPoPReplay("token", "client")
	output := logs.String()
	for _, expected := range []string{`"endpoint":"token"`, `"client_id":"client"`} {
		if !strings.Contains(output, expected) {
			t.Errorf("safe field %s missing from %s", expected, output)
		}
	}
	for _, forbidden := range []string{"remote_addr", "remote_ip", "user_agent", "sid"} {
		if strings.Contains(output, forbidden) {
			t.Errorf("private field %q present in %s", forbidden, output)
		}
	}
}
