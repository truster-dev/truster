// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"github.com/truster-dev/truster/v2/internal/config"
)

const supportedDPoPAlgorithmChallenge = "ES256 ES512"

// stateSatisfiesClientPolicy revalidates policy-sensitive authorization state before final code issuance.
func stateSatisfiesClientPolicy(state *OAuthState, client config.ClientConfig) bool {
	if (client.RequirePAR && !state.PushedAuthorization) || !validateDPoPBinding(client, state.DPoPJKT) {
		return false
	}
	switch state.RefreshMode {
	case "":
		return true
	case "session":
		return client.RefreshTokens.Enabled
	case "offline":
		return client.RefreshTokens.Enabled && client.RefreshTokens.AllowOfflineAccess
	default:
		return false
	}
}

// validateDPoPBinding rejects incomplete bindings and client-profile drift.
func validateDPoPBinding(client config.ClientConfig, jkt string) bool {
	if jkt == "" {
		return client.DPoP.Mode != "required"
	}
	return client.DPoP.Mode == "required"
}

// logDPoPReplay records a distinct endpoint-boundary security event without request or proof identifiers.
func (s *Server) logDPoPReplay(endpoint, clientID string) {
	if s.logger != nil {
		s.logger.Warn("DPoP proof replay rejected", "endpoint", endpoint, "client_id", clientID)
	}
}
