// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"time"

	"github.com/truster-dev/truster/v2/internal/statedb"
)

const authorizationStateTTL = 10 * time.Minute

// OAuthState represents the OAuth2 state parameter data.
// It contains client information and PKCE details that need to be preserved across the OAuth flow.
type OAuthState struct {
	FlowID              string
	ConnectorID         string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	Nonce               string
	OIDCState           string
	Scopes              string
	RefreshMode         string
	AuthTime            time.Time
	OfflineConsent      bool
	Purpose             string
	DPoPJKT             string
	PushedAuthorization bool
}

// EncodeState creates a new random state token and stores the OAuth state data.
// The token expires in 10 minutes and is used to prevent CSRF attacks.
func (m *AuthCodeManager) EncodeState(state OAuthState) (string, error) {
	stateToken, err := statedb.GenerateStateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	now := time.Now()
	oauthState := &statedb.OAuthState{
		StateToken:    stateToken,
		ClientID:      state.ClientID,
		RedirectURI:   state.RedirectURI,
		CodeChallenge: state.CodeChallenge,
		Nonce:         state.Nonce,
		OIDCState:     state.OIDCState,
		CreatedAt:     now,
		ExpiresAt:     now.Add(authorizationStateTTL),
		ConnectorID:   state.ConnectorID,
		Scopes:        state.Scopes, RefreshMode: state.RefreshMode, AuthTime: state.AuthTime,
		OfflineConsent:      state.OfflineConsent,
		Purpose:             state.Purpose,
		DPoPJKT:             state.DPoPJKT,
		PushedAuthorization: state.PushedAuthorization,
	}

	if err := m.store.SaveState(oauthState); err != nil {
		return "", fmt.Errorf("failed to save state: %w", err)
	}

	return stateToken, nil
}

// DecodeState validates and retrieves a state token, extracting the OAuth state data.
// The state token is atomically retrieved and deleted to enforce single-use and prevent replay attacks.
func (m *AuthCodeManager) DecodeState(stateToken string) (*OAuthState, error) {
	storedState, err := m.store.GetAndDeleteState(stateToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state token: %w", err)
	}
	return oauthStateFromStored(storedState), nil
}

// PeekState validates and retrieves a state token without consuming it.
func (m *AuthCodeManager) PeekState(stateToken string) (*OAuthState, error) {
	storedState, err := m.store.PeekState(stateToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state token: %w", err)
	}
	return oauthStateFromStored(storedState), nil
}

// oauthStateFromStored converts a persisted state to its OIDC representation.
func oauthStateFromStored(storedState *statedb.OAuthState) *OAuthState {
	return &OAuthState{FlowID: storedState.StateToken, ClientID: storedState.ClientID, RedirectURI: storedState.RedirectURI, CodeChallenge: storedState.CodeChallenge, Nonce: storedState.Nonce, OIDCState: storedState.OIDCState, ConnectorID: storedState.ConnectorID, Scopes: storedState.Scopes, RefreshMode: storedState.RefreshMode, AuthTime: storedState.AuthTime, OfflineConsent: storedState.OfflineConsent, Purpose: storedState.Purpose, DPoPJKT: storedState.DPoPJKT, PushedAuthorization: storedState.PushedAuthorization}
}
