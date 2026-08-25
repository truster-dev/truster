// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"
)

// Store provides persistent storage for OAuth flows and single-use credentials.
type Store struct {
	db         *database
	logger     *slog.Logger
	cancel     context.CancelFunc
	cleanupCtx context.Context
	done       chan struct{}
	postgresql bool
}

// OAuthState represents stored OAuth state parameters.
type OAuthState struct {
	StateToken          string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	Nonce               string
	OIDCState           string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	ConnectorID         string
	Scopes              string
	RefreshMode         string
	AuthTime            time.Time
	OfflineConsent      bool
	Purpose             string
	DPoPJKT             string
	PushedAuthorization bool
}

// AuthCode represents a stored authorization code.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	Email               string
	EmailVerified       bool
	Nonce               string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Scopes              string
	RefreshMode         string
	AuthTime            time.Time
	ConnectorID         string
	UpstreamSubject     string
	OfflineConsent      bool
	DPoPJKT             string
	PushedAuthorization bool
}

// PushedRequest is a short-lived, one-time RFC 9126 authorization request.
type PushedRequest struct {
	RequestURI, ClientID, RedirectURI, ResponseType, Scopes, State, Nonce string
	CodeChallenge, CodeChallengeMethod, Prompt, DPoPJKT                   string
	CreatedAt, ExpiresAt                                                  time.Time
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
	return s.db.Close()
}

// Ready reports whether the authoritative database can answer within its query timeout.
func (s *Store) Ready(ctx context.Context) error {
	ctx, cancel := s.db.operationContext(ctx)
	defer cancel()
	var err error
	if s.postgresql {
		err = CheckRuntime(ctx, s.db)
	} else {
		err = s.db.PingContext(ctx)
	}
	if err != nil {
		return fmt.Errorf("state database unavailable: %w", err)
	}
	return nil
}

// GenerateStateToken creates a new cryptographically secure random state token.
func GenerateStateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateAuthCode creates a new cryptographically secure random authorization code.
func GenerateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SaveState stores an OAuth state token.
func (s *Store) SaveState(state *OAuthState) error {
	query := `
		INSERT INTO {{state}}oauth_states (state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at, connector_id, scopes, refresh_mode, auth_time, offline_consent, purpose, dpop_jkt, pushed_authorization)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`
	_, err := s.db.Exec(query,
		state.StateToken,
		state.ClientID,
		state.RedirectURI,
		state.CodeChallenge,
		state.Nonce,
		state.OIDCState,
		state.CreatedAt,
		state.ExpiresAt,
		state.ConnectorID,
		state.Scopes, state.RefreshMode, state.AuthTime, state.OfflineConsent, state.Purpose, nullable(state.DPoPJKT), state.PushedAuthorization,
	)
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}
	return nil
}

// GetAndDeleteState retrieves and atomically deletes a state token (single-use enforcement).
func (s *Store) GetAndDeleteState(stateToken string) (*OAuthState, error) {
	var state OAuthState
	query := `
		DELETE FROM {{state}}oauth_states
		WHERE state_token = $1 AND expires_at >= $2
		RETURNING state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at, connector_id, scopes, refresh_mode, auth_time, offline_consent, purpose, COALESCE(dpop_jkt,''), pushed_authorization
	`
	err := s.db.QueryRow(query, stateToken, time.Now()).Scan(
		&state.StateToken,
		&state.ClientID,
		&state.RedirectURI,
		&state.CodeChallenge,
		&state.Nonce,
		&state.OIDCState,
		&state.CreatedAt,
		&state.ExpiresAt,
		&state.ConnectorID,
		&state.Scopes, &state.RefreshMode, &state.AuthTime, &state.OfflineConsent, &state.Purpose, &state.DPoPJKT, &state.PushedAuthorization,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("state token not found, expired, or already used")
	}
	if err != nil {
		return nil, fmt.Errorf("consume state: %w", err)
	}
	if time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("state token has expired")
	}
	return &state, nil
}

// PeekState retrieves a valid state token without consuming it.
func (s *Store) PeekState(stateToken string) (*OAuthState, error) {
	var state OAuthState
	err := s.db.QueryRow(`SELECT state_token,client_id,redirect_uri,code_challenge,nonce,oidc_state,created_at,expires_at,connector_id,scopes,refresh_mode,auth_time,offline_consent,purpose,COALESCE(dpop_jkt,''),pushed_authorization FROM {{state}}oauth_states WHERE state_token=$1`, stateToken).Scan(
		&state.StateToken, &state.ClientID, &state.RedirectURI, &state.CodeChallenge, &state.Nonce, &state.OIDCState, &state.CreatedAt, &state.ExpiresAt, &state.ConnectorID, &state.Scopes, &state.RefreshMode, &state.AuthTime, &state.OfflineConsent, &state.Purpose, &state.DPoPJKT, &state.PushedAuthorization)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("state token not found or already used")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve state: %w", err)
	}
	if time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("state token has expired")
	}
	return &state, nil
}

// SaveCredential records a credential only after its email has been accepted.
func (s *Store) SaveCredential(connectorID, subject, email string, local bool, verifiedAt time.Time) error {
	query := `INSERT INTO {{state}}upstream_credentials(connector_id,subject,email,verified_at,local_verified) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(connector_id,subject,email) DO UPDATE SET verified_at=excluded.verified_at,local_verified=MAX(local_verified,excluded.local_verified)`
	if s.postgresql {
		query = `INSERT INTO {{state}}upstream_credentials(connector_id,subject,email,verified_at,local_verified) VALUES($1,$2,$3,$4,$5)
			ON CONFLICT(connector_id,subject,email) DO UPDATE SET verified_at=excluded.verified_at,local_verified=(upstream_credentials.local_verified OR excluded.local_verified)`
	}
	_, err := s.db.Exec(query, connectorID, subject, email, verifiedAt, local)
	if err != nil {
		return fmt.Errorf("failed to save upstream credential: %w", err)
	}
	return nil
}

// CredentialVerified reports whether this exact connector identity and email was accepted before.
func (s *Store) CredentialVerified(connectorID, subject, email string) (exists, local bool, err error) {
	var value bool
	err = s.db.QueryRow(`SELECT local_verified FROM {{state}}upstream_credentials WHERE connector_id=$1 AND subject=$2 AND email=$3`, connectorID, subject, email).Scan(&value)
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	return err == nil, value, err
}

// SaveAuthCode stores an authorization code.
func (s *Store) SaveAuthCode(code *AuthCode) error {
	query := `
		INSERT INTO {{state}}auth_codes (code, client_id, redirect_uri, code_challenge, email, email_verified, nonce, created_at, expires_at, scopes, refresh_mode, auth_time, connector_id, upstream_subject, offline_consent, dpop_jkt, pushed_authorization)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := s.db.Exec(query,
		code.Code,
		code.ClientID,
		code.RedirectURI,
		code.CodeChallenge,
		code.Email,
		code.EmailVerified,
		code.Nonce,
		code.CreatedAt,
		code.ExpiresAt,
		code.Scopes, code.RefreshMode, code.AuthTime, code.ConnectorID, code.UpstreamSubject, code.OfflineConsent, nullable(code.DPoPJKT), code.PushedAuthorization,
	)
	if err != nil {
		return fmt.Errorf("failed to save auth code: %w", err)
	}
	return nil
}

// PeekAuthCode retrieves a valid authorization code without consuming it.
func (s *Store) PeekAuthCode(codeStr string, now time.Time) (*AuthCode, error) {
	var code AuthCode
	err := s.db.QueryRow(`SELECT code,client_id,redirect_uri,code_challenge,email,email_verified,nonce,created_at,expires_at,scopes,refresh_mode,auth_time,connector_id,upstream_subject,offline_consent,COALESCE(dpop_jkt,''),pushed_authorization FROM {{state}}auth_codes WHERE code=$1`, codeStr).Scan(
		&code.Code, &code.ClientID, &code.RedirectURI, &code.CodeChallenge, &code.Email, &code.EmailVerified, &code.Nonce, &code.CreatedAt, &code.ExpiresAt, &code.Scopes, &code.RefreshMode, &code.AuthTime, &code.ConnectorID, &code.UpstreamSubject, &code.OfflineConsent, &code.DPoPJKT, &code.PushedAuthorization)
	if err == sql.ErrNoRows || (err == nil && !now.Before(code.ExpiresAt)) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("peek authorization code: %w", err)
	}
	return &code, nil
}

// GetAndDeleteAuthCode retrieves and atomically deletes an authorization code (single-use enforcement).
func (s *Store) GetAndDeleteAuthCode(codeStr string) (*AuthCode, error) {
	var code AuthCode
	query := `
		DELETE FROM {{state}}auth_codes
		WHERE code = $1 AND expires_at >= $2
		RETURNING code, client_id, redirect_uri, code_challenge, email, email_verified, nonce, created_at, expires_at, scopes, refresh_mode, auth_time, connector_id, upstream_subject, offline_consent, COALESCE(dpop_jkt,''), pushed_authorization
	`
	err := s.db.QueryRow(query, codeStr, time.Now()).Scan(
		&code.Code,
		&code.ClientID,
		&code.RedirectURI,
		&code.CodeChallenge,
		&code.Email,
		&code.EmailVerified,
		&code.Nonce,
		&code.CreatedAt,
		&code.ExpiresAt,
		&code.Scopes, &code.RefreshMode, &code.AuthTime, &code.ConnectorID, &code.UpstreamSubject, &code.OfflineConsent, &code.DPoPJKT, &code.PushedAuthorization,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("authorization code not found, expired, or already used")
	}
	if err != nil {
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	if time.Now().After(code.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}
	return &code, nil
}

// nullable stores absent DPoP profile values as SQL NULL.
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// cleanupExpired periodically removes expired state tokens and authorization codes.
func (s *Store) cleanupExpired(ctx context.Context) {
	defer close(s.done)
	ordinary := time.NewTicker(10 * time.Minute)
	protocol := time.NewTicker(5 * time.Second)
	defer ordinary.Stop()
	defer protocol.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ordinary.C:
			s.cleanupExpiredAtContext(ctx, time.Now())
		case <-protocol.C:
			s.cleanupProtocolState(time.Now())
		}
	}
}

// cleanupExpiredAt removes records whose safe retention period has elapsed.
func (s *Store) cleanupExpiredAt(now time.Time) {
	s.cleanupProtocolState(now)
	s.cleanupExpiredAtContext(context.Background(), now)
}

// cleanupProtocolState runs frequent bounded cleanup for short-lived PAR rows.
func (s *Store) cleanupProtocolState(now time.Time) {
	if err := s.cleanupPARRequests(now.UTC()); err != nil && s.logger != nil {
		s.logger.Error("failed to clean up PAR requests", "error", err)
	}
}

// cleanupExpiredAtContext removes expired records using a cancellable cleanup context.
func (s *Store) cleanupExpiredAtContext(ctx context.Context, now time.Time) {
	result, err := s.deleteExpiredBatchContext(ctx, "oauth_states", "expires_at < $1", now)
	if err != nil {
		s.logger.Error("failed to clean up expired states", "error", err)
	} else if count, rowsErr := result.RowsAffected(); rowsErr == nil && count > 0 {
		s.logger.Debug("cleaned up expired states", "count", count)
	}

	result, err = s.deleteExpiredBatchContext(ctx, "auth_codes", "expires_at < $1", now)
	if err != nil {
		s.logger.Error("failed to clean up expired auth codes", "error", err)
	} else if count, rowsErr := result.RowsAffected(); rowsErr == nil && count > 0 {
		s.logger.Debug("cleaned up expired auth codes", "count", count)
	}
	_, _ = s.deleteExpiredBatchContext(ctx, "otp_challenges", "expires_at < $1", now)
	_, _ = s.deleteExpiredBatchContext(ctx, "otp_sends", "sent_at < $1", now.Add(-time.Hour))
	_, _ = s.deleteExpiredBatchContext(ctx, "grant_actions", "expires_at <= $1", now)
	_, _ = s.deleteExpiredBatchContext(ctx, "identity_selections", "expires_at <= $1", now)
	_, _ = s.deleteExpiredBatchContext(ctx, "flow_credentials", "expires_at <= $1", now)
	_, _ = s.deleteExpiredBatchContext(ctx, "refresh_grants", "absolute_expires_at <= $1", now)
	if !s.postgresql {
		if _, err := s.db.ExecContext(ctx, "PRAGMA optimize"); err != nil {
			s.logger.Error("failed to optimize database", "error", err)
		}
	}
}

// lockRows returns the PostgreSQL row-locking clause used by consuming reads.
func (s *Store) lockRows() string {
	if s.postgresql {
		return " FOR UPDATE"
	}
	return ""
}

// lockJoinedRows returns the PostgreSQL row-locking clause for grant/token reads.
func (s *Store) lockJoinedRows() string {
	if s.postgresql {
		return " FOR UPDATE OF g,t"
	}
	return ""
}

// deleteExpiredBatchContext removes an eligible batch with caller cancellation.
func (s *Store) deleteExpiredBatchContext(ctx context.Context, table, predicate string, value any) (sql.Result, error) {
	table = stateSchemaToken + table
	if s.postgresql {
		query := fmt.Sprintf("DELETE FROM %s WHERE ctid IN (SELECT ctid FROM %s WHERE %s LIMIT 500 FOR UPDATE SKIP LOCKED)", table, table, predicate)
		return s.db.ExecContext(ctx, query, value)
	}
	query := fmt.Sprintf("DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s LIMIT 500)", table, table, predicate)
	return s.db.ExecContext(ctx, query, value)
}
