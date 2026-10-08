// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"time"

	"github.com/truster-dev/truster/v3/internal/statedb"
)

// AuthCodeManager handles authorization code creation and validation using the state database.
// It provides replay protection through single-use enforcement and automatic cleanup of expired codes.
type AuthCodeManager struct {
	store *statedb.Store
}

// AuthCodePayload contains the information embedded in an authorization code.
type AuthCodePayload struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	Email               string
	EmailVerified       bool
	Nonce               string
	Scopes              string
	RefreshMode         string
	AuthTime            time.Time
	ConnectorID         string
	UpstreamSubject     string
	OfflineConsent      bool
	DPoPJKT             string
	PushedAuthorization bool
}

// NewAuthCodeManager creates and initializes an authorization code manager.
func NewAuthCodeManager(store *statedb.Store) (*AuthCodeManager, error) {
	mgr := &AuthCodeManager{
		store: store,
	}

	return mgr, nil
}

// GenerateCode creates a new authorization code containing the provided payload.
// The code is a cryptographically secure random token that expires in 5 minutes.
func (m *AuthCodeManager) GenerateCode(payload AuthCodePayload) (string, error) {
	code, err := statedb.GenerateAuthCode()
	if err != nil {
		return "", fmt.Errorf("failed to generate auth code: %w", err)
	}

	now := time.Now()
	authCode := &statedb.AuthCode{
		Code:          code,
		ClientID:      payload.ClientID,
		RedirectURI:   payload.RedirectURI,
		CodeChallenge: payload.CodeChallenge,
		Email:         payload.Email,
		EmailVerified: payload.EmailVerified,
		Nonce:         payload.Nonce,
		CreatedAt:     now,
		ExpiresAt:     now.Add(5 * time.Minute),
		Scopes:        payload.Scopes, RefreshMode: payload.RefreshMode, AuthTime: payload.AuthTime,
		ConnectorID: payload.ConnectorID, UpstreamSubject: payload.UpstreamSubject,
		OfflineConsent:      payload.OfflineConsent,
		DPoPJKT:             payload.DPoPJKT,
		PushedAuthorization: payload.PushedAuthorization,
	}

	if err := m.store.SaveAuthCode(authCode); err != nil {
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}

	return code, nil
}

// Peek validates an authorization code without consuming it.
func (m *AuthCodeManager) Peek(code string) (*statedb.AuthCode, error) {
	return m.store.PeekAuthCode(code, time.Now())
}

// ValidateAndExtract validates an authorization code and extracts its payload.
// The code is atomically retrieved and deleted to enforce single-use.
func (m *AuthCodeManager) ValidateAndExtract(code string) (*AuthCodePayload, error) {
	authCode, err := m.store.GetAndDeleteAuthCode(code)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired authorization code: %w", err)
	}

	payload := &AuthCodePayload{
		ClientID:      authCode.ClientID,
		RedirectURI:   authCode.RedirectURI,
		CodeChallenge: authCode.CodeChallenge,
		Email:         authCode.Email,
		EmailVerified: authCode.EmailVerified,
		Nonce:         authCode.Nonce,
		Scopes:        authCode.Scopes, RefreshMode: authCode.RefreshMode, AuthTime: authCode.AuthTime,
		ConnectorID: authCode.ConnectorID, UpstreamSubject: authCode.UpstreamSubject,
		OfflineConsent:      authCode.OfflineConsent,
		DPoPJKT:             authCode.DPoPJKT,
		PushedAuthorization: authCode.PushedAuthorization,
	}

	return payload, nil
}
