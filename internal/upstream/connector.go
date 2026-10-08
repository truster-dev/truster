// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/truster-dev/truster/v3/internal/config"
	"golang.org/x/oauth2"
)

// Credential is the normalized, persistable upstream OAuth credential.
type Credential struct {
	AccessToken       string    `json:"access_token"`
	TokenType         string    `json:"token_type,omitempty"`
	RefreshToken      string    `json:"refresh_token,omitempty"`
	AccessExpiry      time.Time `json:"access_expiry,omitempty"`
	RefreshExpiry     time.Time `json:"refresh_expiry,omitempty"`
	AccessNonExpiring bool      `json:"access_non_expiring,omitempty"`
}

// OAuthToken creates the runtime oauth2 token without relying on raw extras.
func (c *Credential) OAuthToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: c.AccessToken, TokenType: c.TokenType, RefreshToken: c.RefreshToken, Expiry: c.AccessExpiry}
}

// NormalizeCredential captures known expiry metadata before oauth2 token extras are lost.
func NormalizeCredential(token *oauth2.Token, now time.Time, accessNonExpiring bool) *Credential {
	c := &Credential{AccessToken: token.AccessToken, TokenType: token.TokenType, RefreshToken: token.RefreshToken, AccessExpiry: token.Expiry, AccessNonExpiring: accessNonExpiring && token.Expiry.IsZero()}
	for _, name := range []string{"refresh_expires_in", "refresh_token_expires_in"} {
		if seconds, ok := extraSeconds(token.Extra(name)); ok {
			c.RefreshExpiry = now.Add(time.Duration(seconds) * time.Second)
			break
		}
	}
	if c.AccessExpiry.IsZero() {
		if seconds, ok := extraSeconds(token.Extra("expires_in")); ok {
			c.AccessExpiry = now.Add(time.Duration(seconds) * time.Second)
			c.AccessNonExpiring = false
		}
	}
	return c
}

// extraSeconds parses the common numeric and string OAuth extra representations.
func extraSeconds(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), v > 0
	case int64:
		return v, v > 0
	case json.Number:
		n, err := v.Int64()
		return n, err == nil && n > 0
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil && n > 0
	default:
		return 0, false
	}
}

// Connector is the interface for upstream OAuth2/OIDC providers.
// It handles the OAuth2 flow, credential renewal, and identity retrieval.
type Connector interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string) (*Credential, error)
	Refresh(ctx context.Context, credential *Credential) (*Credential, error)
	GetIdentity(ctx context.Context, token *oauth2.Token) (Identity, error)
}

// Email is an email assertion returned by an upstream provider.
type Email struct {
	Address  string
	Verified bool
	Primary  bool
}

// Identity is a stable upstream subject and all of its email assertions.
type Identity struct {
	Subject string
	Emails  []Email
}

// NewConnector creates a new upstream connector based on the configuration.
// Supported types are "google", "github", and "generic".
// The redirect URL is automatically constructed as {issuerURL}/callback/{type}.
func NewConnector(cfg config.ConnectorConfig, redirectURL, clientID, clientSecret string) (Connector, error) {
	switch cfg.Type {
	case "google":
		return NewGoogleConnector(cfg, redirectURL, clientID, clientSecret), nil
	case "github":
		return NewGitHubConnector(cfg, redirectURL, clientID, clientSecret), nil
	case "generic":
		return NewGenericConnector(cfg, redirectURL, clientID, clientSecret), nil
	default:
		return nil, fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}
}
