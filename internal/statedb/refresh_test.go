// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRefreshReplayRevokesFamily verifies retries compromise the replacement family.
func TestRefreshReplayRevokesFamily(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	current, err := GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	grant := RefreshGrant{SID: "sid", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err := store.CreateRefreshGrant(grant, current, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	other, err := GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsFound := make(chan error, 2)
	for _, candidate := range []RefreshMaterial{replacement, other} {
		wg.Add(1)
		go func(candidate RefreshMaterial) {
			defer wg.Done()
			_, _, rotateErr := store.RotateRefreshToken(current, candidate, "client", now.Add(time.Minute))
			errorsFound <- rotateErr
		}(candidate)
	}
	wg.Wait()
	close(errorsFound)
	successes, replays := 0, 0
	for rotateErr := range errorsFound {
		if rotateErr == nil {
			successes++
		}
		if errors.Is(rotateErr, ErrRefreshReplay) {
			replays++
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("successes=%d replays=%d", successes, replays)
	}
	for _, candidate := range []RefreshMaterial{replacement, other} {
		if _, _, err := store.PrepareRefresh(candidate, "client", now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("candidate after replay = %v", err)
		}
	}
}

// TestClaimedRefreshReplayRevokesWinner verifies a connector refresh loser compromises the winner's replacement.
func TestClaimedRefreshReplayRevokesWinner(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	current, _ := GenerateRefreshMaterial()
	replacement, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "connector-sid", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "google", UpstreamSubject: "subject", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err := store.CreateRefreshGrant(grant, current, []byte{1}, []byte{2}, now); err != nil {
		t.Fatal(err)
	}
	claimed, claim, _, err := store.ClaimRefresh(current, "client", now.Add(time.Minute), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CompleteClaimedRefresh(current, replacement, claimed, claim, []byte{3}, []byte{4}, grant.AbsoluteExpiry, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = store.ClaimRefresh(current, "client", now.Add(3*time.Minute), time.Minute); !errors.Is(err, ErrRefreshReplay) {
		t.Fatalf("loser = %v", err)
	}
	if _, _, err = store.PrepareRefresh(replacement, "client", now.Add(4*time.Minute)); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("winner replacement after replay = %v", err)
	}
}

// TestClaimedReplayAfterOldExpiryRevokesWinner covers the consumed-token expiry boundary.
func TestClaimedReplayAfterOldExpiryRevokesWinner(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	current, _ := GenerateRefreshMaterial()
	replacement, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "expiry-replay", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "google", UpstreamSubject: "subject", Mode: "session", AuthTime: now, IdleTTL: time.Minute, AbsoluteExpiry: now.Add(3 * time.Minute)}
	if err := store.CreateRefreshGrant(grant, current, []byte{1}, []byte{2}, now); err != nil {
		t.Fatal(err)
	}
	claimed, claim, _, err := store.ClaimRefresh(current, "client", now.Add(30*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CompleteClaimedRefresh(current, replacement, claimed, claim, []byte{3}, []byte{4}, grant.AbsoluteExpiry, now.Add(time.Minute-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = store.ClaimRefresh(current, "client", now.Add(time.Minute+time.Nanosecond), time.Minute); !errors.Is(err, ErrRefreshReplay) {
		t.Fatalf("loser = %v", err)
	}
	if _, _, err = store.PrepareRefresh(replacement, "client", now.Add(time.Minute+time.Second)); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("replacement = %v", err)
	}
}

// TestCompleteClaimedRefreshRechecksExpiry verifies completion cannot cross a grant boundary.
func TestCompleteClaimedRefreshRechecksExpiry(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	current, _ := GenerateRefreshMaterial()
	replacement, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "boundary", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "google", UpstreamSubject: "subject", Mode: "session", AuthTime: now, IdleTTL: time.Minute, AbsoluteExpiry: now.Add(2 * time.Minute)}
	if err := store.CreateRefreshGrant(grant, current, []byte{1}, []byte{2}, now); err != nil {
		t.Fatal(err)
	}
	claimed, claim, _, err := store.ClaimRefresh(current, "client", now.Add(30*time.Second), 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CompleteClaimedRefresh(current, replacement, claimed, claim, []byte{3}, []byte{4}, grant.AbsoluteExpiry, now.Add(time.Minute)); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("completion at idle boundary = %v", err)
	}
	if _, _, err = store.PrepareRefresh(current, "client", now.Add(31*time.Second)); err != nil {
		t.Fatalf("original token was consumed: %v", err)
	}
}

// TestSQLiteForeignKeysApplyToPooledConnections verifies DSN pragmas cover every connection.
func TestSQLiteForeignKeysApplyToPooledConnections(t *testing.T) {
	store := otpStore(t)
	for i := 0; i < 12; i++ {
		if _, err := store.db.Exec(`INSERT INTO refresh_tokens(handle_hash,token_hash,sid,issued_at,expires_at) VALUES($1,$2,$3,$4,$5)`, []byte{byte(i)}, []byte{byte(i)}, "missing", time.Now(), time.Now().Add(time.Hour)); err == nil {
			t.Fatal("foreign key violation unexpectedly succeeded")
		}
	}
}

// TestGrantActionsAreBoundExpiringAndSingleUse verifies self-service revocation invariants.
func TestGrantActionsAreBoundExpiringAndSingleUse(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	material, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "managed", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err := store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		token, email, sid, action string
		expiry                    time.Time
	}{
		{"wrong-email", "other@example.com", "managed", "revoke", now.Add(time.Minute)},
		{"wrong-sid", "user@example.com", "managed", "revoke", now.Add(time.Minute)},
		{"wrong-action", "user@example.com", "managed", "inspect", now.Add(time.Minute)},
		{"expired", "user@example.com", "managed", "revoke", now.Add(-time.Second)},
	} {
		if err := store.CreateGrantAction(test.token, test.email, test.sid, test.action, now, test.expiry); err != nil {
			t.Fatal(err)
		}
		consumeSID := "managed"
		if test.token == "wrong-sid" {
			consumeSID = "other"
		}
		if got := store.ConsumeGrantActionAndRevoke(test.token, "user@example.com", consumeSID, "revoke", now); !errors.Is(got, ErrInvalidGrant) {
			t.Fatalf("mismatch %s = %v", test.token, got)
		}
	}
	if err := store.CreateGrantAction("valid", "user@example.com", "managed", "revoke", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeGrantActionAndRevoke("valid", "user@example.com", "managed", "revoke", now); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeGrantActionAndRevoke("valid", "user@example.com", "managed", "revoke", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("replay = %v", err)
	}
}

// TestConsumeAuthCodeRechecksBindingAndRollsBackCollision verifies the authoritative transaction boundary.
func TestConsumeAuthCodeRechecksBindingAndRollsBackCollision(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	code := &AuthCode{Code: "code", ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: "challenge", Email: "user@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Scopes: "openid", RefreshMode: "session", AuthTime: now, ConnectorID: "email"}
	if err := store.SaveAuthCode(code); err != nil {
		t.Fatal(err)
	}
	expected, err := store.PeekAuthCode(code.Code, now)
	if err != nil {
		t.Fatal(err)
	}
	material, _ := GenerateRefreshMaterial()
	existing := RefreshGrant{SID: "existing", ClientID: "client", Email: code.Email, Scopes: code.Scopes, ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err = store.CreateRefreshGrant(existing, material, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	grant := existing
	grant.SID = "new"
	valid := AuthCodeBinding{ClientID: code.ClientID, RedirectURI: code.RedirectURI, CodeChallenge: code.CodeChallenge}
	for _, binding := range []AuthCodeBinding{
		{ClientID: "other", RedirectURI: code.RedirectURI, CodeChallenge: code.CodeChallenge},
		{ClientID: code.ClientID, RedirectURI: "https://other.example/callback", CodeChallenge: code.CodeChallenge},
		{ClientID: code.ClientID, RedirectURI: code.RedirectURI, CodeChallenge: "other"},
	} {
		if err = store.ConsumeAuthCode(*expected, binding, &grant, material, now); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("binding %#v = %v", binding, err)
		}
	}
	if err = store.ConsumeAuthCode(*expected, valid, &grant, material, now); !errors.Is(err, ErrRefreshCollision) {
		t.Fatalf("collision = %v", err)
	}
	if _, err = store.PeekAuthCode(code.Code, now); err != nil {
		t.Fatalf("collision consumed code: %v", err)
	}
	var grants int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM refresh_grants WHERE sid='new'`).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("rolled-back grant count = %d, err=%v", grants, err)
	}
	fresh, _ := GenerateRefreshMaterial()
	if err = store.ConsumeAuthCode(*expected, valid, &grant, fresh, now); err != nil {
		t.Fatalf("retry after collision: %v", err)
	}
}

// TestRefreshCollisionRollsBackRotation verifies a colliding replacement does not consume the current token.
func TestRefreshCollisionRollsBackRotation(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	current, _ := GenerateRefreshMaterial()
	collision, _ := GenerateRefreshMaterial()
	grant := RefreshGrant{SID: "current", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	other := grant
	other.SID = "collision"
	if err := store.CreateRefreshGrant(grant, current, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRefreshGrant(other, collision, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RotateRefreshToken(current, collision, "client", now.Add(time.Minute)); !errors.Is(err, ErrRefreshCollision) {
		t.Fatalf("rotation collision = %v", err)
	}
	if _, _, err := store.PrepareRefresh(current, "client", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("collision consumed current token: %v", err)
	}
}

// TestParseRefreshTokenRejectsNonCanonicalValues verifies strict ert1 parsing.
func TestParseRefreshTokenRejectsNonCanonicalValues(t *testing.T) {
	material, _ := GenerateRefreshMaterial()
	parts := strings.Split(material.Token, ".")
	for _, token := range []string{"", "ert2." + parts[1] + "." + parts[2], material.Token + ".extra", "ert1." + parts[1] + "=." + parts[2], "ert1." + parts[1] + "." + parts[2] + "=", "ert1.\n" + parts[1] + "." + parts[2]} {
		if _, err := ParseRefreshToken(token); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("ParseRefreshToken(%q) = %v", token, err)
		}
	}
}

// TestRefreshCrashProcess performs one checkpoint and exits without closing SQLite.
func TestRefreshCrashProcess(t *testing.T) {
	scenario := os.Getenv("TRUSTER_CRASH_SCENARIO")
	if scenario == "" {
		t.Skip("subprocess helper")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLite(os.Getenv("TRUSTER_CRASH_DB"), logger)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ParseRefreshToken(os.Getenv("TRUSTER_CRASH_CURRENT"))
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, os.Getenv("TRUSTER_CRASH_NOW"))
	if err != nil {
		t.Fatal(err)
	}
	grant, claim, _, err := store.ClaimRefresh(current, "client", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if scenario != "before-marker" {
		if err = store.MarkUpstreamRefreshStarted(grant.SID, claim, now); err != nil {
			t.Fatal(err)
		}
	}
	if scenario == "after-commit" {
		replacement, parseErr := ParseRefreshToken(os.Getenv("TRUSTER_CRASH_REPLACEMENT"))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		credential := []byte(`{"access_token":"updated"}`)
		nonce, ciphertext, encryptErr := EncryptCredential(replacement.Secret, grant.SID, grant.ClientID, grant.ConnectorID, credential)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		if _, err = store.CompleteClaimedRefresh(current, replacement, grant, claim, nonce, ciphertext, grant.AbsoluteExpiry, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	os.Exit(0)
}

// TestRefreshCrashRestartBoundaries verifies durable storage across abrupt process exits.
func TestRefreshCrashRestartBoundaries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	newGrant := func(t *testing.T, sid string) (string, RefreshGrant, RefreshMaterial, time.Time) {
		t.Helper()
		path := t.TempDir() + "/restart.db"
		store, err := NewSQLite(path, logger)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		material, err := GenerateRefreshMaterial()
		if err != nil {
			t.Fatal(err)
		}
		grant := RefreshGrant{SID: sid, ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "google", UpstreamSubject: "subject", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
		if err = store.CreateRefreshGrant(grant, material, []byte{1}, []byte{2}, now); err != nil {
			t.Fatal(err)
		}
		if err = store.Close(); err != nil {
			t.Fatal(err)
		}
		return path, grant, material, now
	}
	open := func(t *testing.T, path string) *Store {
		t.Helper()
		store, err := NewSQLite(path, logger)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	crash := func(t *testing.T, scenario, path string, current, replacement RefreshMaterial, now time.Time) {
		t.Helper()
		command := exec.Command(os.Args[0], "-test.run=^TestRefreshCrashProcess$")
		command.Env = append(os.Environ(),
			"TRUSTER_CRASH_SCENARIO="+scenario,
			"TRUSTER_CRASH_DB="+path,
			"TRUSTER_CRASH_CURRENT="+current.Token,
			"TRUSTER_CRASH_REPLACEMENT="+replacement.Token,
			"TRUSTER_CRASH_NOW="+now.Format(time.RFC3339Nano),
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("crash helper: %v\n%s", err, output)
		}
	}

	t.Run("before upstream refresh started", func(t *testing.T) {
		path, _, material, now := newGrant(t, "before-marker")
		crash(t, "before-marker", path, material, RefreshMaterial{}, now)
		store := open(t, path)
		_, reclaimed, _, err := store.ClaimRefresh(material, "client", now.Add(time.Minute+time.Nanosecond), time.Minute)
		if err != nil {
			t.Fatalf("reclaim after restart: %v", err)
		}
		if reclaimed.ID == "" {
			t.Fatal("reclaimed claim has no ID")
		}
	})

	t.Run("after upstream refresh started", func(t *testing.T) {
		path, _, material, now := newGrant(t, "after-marker")
		crash(t, "after-marker", path, material, RefreshMaterial{}, now)
		store := open(t, path)
		if _, _, _, err := store.ClaimRefresh(material, "client", now.Add(time.Minute+time.Nanosecond), time.Minute); !errors.Is(err, ErrCredentialIndeterminate) {
			t.Fatalf("claim after restart = %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store = open(t, path)
		if _, _, err := store.PrepareRefresh(material, "client", now.Add(time.Minute+time.Second)); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("indeterminate grant was not durably revoked: %v", err)
		}
	})

	t.Run("after final commit", func(t *testing.T) {
		path, grant, current, now := newGrant(t, "after-commit")
		replacement, err := GenerateRefreshMaterial()
		if err != nil {
			t.Fatal(err)
		}
		crash(t, "after-commit", path, current, replacement, now)
		store := open(t, path)
		var clean int
		if err = store.db.QueryRow(`SELECT COUNT(*) FROM refresh_grants WHERE sid=$1 AND claim_id IS NULL AND claim_expires_at IS NULL AND upstream_refresh_started=0`, grant.SID).Scan(&clean); err != nil {
			t.Fatal(err)
		}
		if clean != 1 {
			t.Fatal("final commit retained its claim or upstream-refresh marker")
		}
		claimed, claim, _, err := store.ClaimRefresh(replacement, "client", now.Add(2*time.Second), time.Minute)
		if err != nil {
			t.Fatalf("claim committed replacement after restart: %v", err)
		}
		plain, err := DecryptCredential(replacement.Secret, grant.SID, grant.ClientID, grant.ConnectorID, claimed.CredentialNonce, claimed.CredentialCiphertext)
		if err != nil || string(plain) != `{"access_token":"updated"}` {
			t.Fatalf("committed credential = %q, %v", plain, err)
		}
		if err = store.ReleaseRefreshClaim(grant.SID, claim); err != nil {
			t.Fatalf("final commit retained claim marker: %v", err)
		}
	})
}

// TestCredentialSeparationDatabaseLossAndCleanup verifies key separation and fail-closed persistence.
func TestCredentialSeparationDatabaseLossAndCleanup(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	material, _ := GenerateRefreshMaterial()
	plaintext := []byte(`{"access_token":"upstream"}`)
	nonce, ciphertext, err := EncryptCredential(material.Secret, "security", "client", "google", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wrong := [32]byte{1}
	if _, err = DecryptCredential(wrong, "security", "client", "google", nonce, ciphertext); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("database-only credential decryption = %v", err)
	}
	if recovered, err := DecryptCredential(material.Secret, "security", "client", "google", nonce, ciphertext); err != nil || string(recovered) != string(plaintext) {
		t.Fatalf("client-secret decryption = %q, %v", recovered, err)
	}
	grant := RefreshGrant{SID: "security", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "google", UpstreamSubject: "subject", Mode: "session", AuthTime: now, IdleTTL: time.Minute, AbsoluteExpiry: now.Add(2 * time.Minute)}
	if err = store.CreateRefreshGrant(grant, material, nonce, ciphertext, now); err != nil {
		t.Fatal(err)
	}
	store.cleanupExpiredAt(grant.AbsoluteExpiry)
	if _, _, err = store.PrepareRefresh(material, "client", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("token survived absolute-expiry cleanup: %v", err)
	}
	lost := otpStore(t)
	if _, _, err = lost.PrepareRefresh(material, "client", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("token survived database loss: %v", err)
	}
}
