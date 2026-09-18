// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"net/http"

	"github.com/truster-dev/truster/v2/internal/config"
)

// HandleDiscovery handles the OIDC discovery endpoint (/.well-known/openid-configuration).
// It returns the OpenID Connect provider metadata.
func (s *Server) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                                s.config.IssuerURL,
		"authorization_endpoint":                config.PublicEndpointURL(s.config.IssuerURL, "authorize"),
		"token_endpoint":                        config.PublicEndpointURL(s.config.IssuerURL, "token"),
		"revocation_endpoint":                   config.PublicEndpointURL(s.config.IssuerURL, "revoke"),
		"userinfo_endpoint":                     config.PublicEndpointURL(s.config.IssuerURL, "userinfo"),
		"jwks_uri":                              config.PublicEndpointURL(s.config.IssuerURL, "jwks"),
		"pushed_authorization_request_endpoint": config.PublicEndpointURL(s.config.IssuerURL, "par"),
		"dpop_signing_alg_values_supported":     []string{"ES256", "ES512"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{s.config.SigningAlgorithm},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups", "offline_access"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "preferred_username", "groups"},
		"code_challenge_methods_supported":      []string{"S256"},
		"prompt_values_supported":               []string{"none", "login", "create"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
