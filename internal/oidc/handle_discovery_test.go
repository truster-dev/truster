// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/truster-dev/truster/v2/internal/config"
)

func TestHandleDiscoveryAdvertisesConfiguredSigningAlgorithm(t *testing.T) {
	server := NewServer(
		&config.Config{IssuerURL: "https://auth.example.com", SigningAlgorithm: "PS512"},
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	)
	response := httptest.NewRecorder()
	server.HandleDiscovery(response, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	var discovery struct {
		SigningAlgorithms        []string `json:"id_token_signing_alg_values_supported"`
		DPoPSigningAlgorithms    []string `json:"dpop_signing_alg_values_supported"`
		TokenAuthenticationModes []string `json:"token_endpoint_auth_methods_supported"`
		PromptValues             []string `json:"prompt_values_supported"`
	}
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	if len(discovery.SigningAlgorithms) != 1 || discovery.SigningAlgorithms[0] != "PS512" {
		t.Fatalf("signing algorithms = %v, want [PS512]", discovery.SigningAlgorithms)
	}
	if got := discovery.DPoPSigningAlgorithms; len(got) != 2 || got[0] != "ES256" || got[1] != "ES512" {
		t.Fatalf("DPoP signing algorithms = %v, want [ES256 ES512]", got)
	}
	if got := discovery.TokenAuthenticationModes; len(got) != 1 || got[0] != "none" {
		t.Fatalf("token authentication modes = %v, want [none]", got)
	}
	if got := discovery.PromptValues; len(got) != 3 || got[0] != "none" || got[1] != "login" || got[2] != "create" {
		t.Fatalf("prompt values = %v, want [none login create]", got)
	}
}
