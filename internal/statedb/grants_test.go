// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"errors"
	"testing"
	"time"

	"github.com/truster-dev/truster/v2/internal/upstream"
)

// TestIdentitySelectionExtendsActiveOAuthState verifies a late upstream callback gives the chooser its full lifetime.
func TestIdentitySelectionExtendsActiveOAuthState(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	state := &OAuthState{StateToken: "state", ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: "challenge", OIDCState: "oidc-state", CreatedAt: now.Add(-9 * time.Minute), ExpiresAt: now.Add(time.Minute), Scopes: "openid", AuthTime: now.Add(-9 * time.Minute)}
	if err := store.SaveState(state); err != nil {
		t.Fatal(err)
	}
	emails := []upstream.Email{{Address: "user@example.com", Verified: true}}
	before := time.Now()
	if err := store.CreateIdentitySelection("selection", state.StateToken, "github", "123", emails, 10*time.Minute, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	stored, err := store.PeekState(state.StateToken)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ExpiresAt.Before(before.Add(5*time.Minute)) || stored.ExpiresAt.After(after.Add(5*time.Minute)) {
		t.Fatalf("OAuth state expiry = %v, want between %v and %v", stored.ExpiresAt, before.Add(5*time.Minute), after.Add(5*time.Minute))
	}
	gotState, connector, subject, gotEmails, err := store.ConsumeIdentitySelection("selection", stored.ExpiresAt.Add(-time.Minute))
	if err != nil || gotState != state.StateToken || connector != "github" || subject != "123" || len(gotEmails) != 1 || gotEmails[0] != emails[0] {
		t.Fatalf("consume selection = %q %q %q %#v, %v", gotState, connector, subject, gotEmails, err)
	}
}

// TestIdentitySelectionRequiresActiveOAuthState verifies a chooser cannot revive a missing, expired, or too-old flow.
func TestIdentitySelectionRequiresActiveOAuthState(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	emails := []upstream.Email{{Address: "user@example.com", Verified: true}}
	if err := store.CreateIdentitySelection("selection", "missing", "github", "123", emails, 10*time.Minute, 5*time.Minute); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("missing OAuth state error = %v, want invalid grant", err)
	}
	if _, _, _, _, err := store.ConsumeIdentitySelection("selection", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("orphaned identity selection error = %v, want invalid grant", err)
	}
	for _, state := range []*OAuthState{
		{StateToken: "expired", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second)},
		{StateToken: "too-old", CreatedAt: now.Add(-10*time.Minute - time.Second), ExpiresAt: now.Add(time.Minute)},
	} {
		state.ClientID, state.RedirectURI, state.CodeChallenge, state.OIDCState, state.Scopes, state.AuthTime = "client", "https://client.example/callback", "challenge", "state", "openid", now
		if err := store.SaveState(state); err != nil {
			t.Fatal(err)
		}
		if err := store.CreateIdentitySelection(state.StateToken+"-selection", state.StateToken, "github", "123", emails, 10*time.Minute, 5*time.Minute); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("OAuth state %q error = %v, want invalid grant", state.StateToken, err)
		}
		if _, _, _, _, err := store.ConsumeIdentitySelection(state.StateToken+"-selection", now); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("OAuth state %q left an identity selection", state.StateToken)
		}
	}
}

// TestIdentitySelectionInsertFailureRollsBackStateExpiry verifies chooser creation remains atomic.
func TestIdentitySelectionInsertFailureRollsBackStateExpiry(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	state := &OAuthState{StateToken: "rollback-state", ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: "challenge", OIDCState: "state", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Scopes: "openid", AuthTime: now}
	if err := store.SaveState(state); err != nil {
		t.Fatal(err)
	}
	emails := []upstream.Email{{Address: "user@example.com", Verified: true}}
	if err := store.CreateIdentitySelection("duplicate", state.StateToken, "github", "123", emails, 10*time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	stored, err := store.PeekState(state.StateToken)
	if err != nil {
		t.Fatal(err)
	}
	before := stored.ExpiresAt
	if err = store.CreateIdentitySelection("duplicate", state.StateToken, "github", "123", emails, 10*time.Minute, 2*time.Minute); err == nil {
		t.Fatal("duplicate identity selection succeeded")
	}
	stored, err = store.PeekState(state.StateToken)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.ExpiresAt.Equal(before) {
		t.Fatalf("OAuth state expiry after rollback = %v, want %v", stored.ExpiresAt, before)
	}
}
