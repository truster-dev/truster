// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrInvalidGrant identifies unknown, malformed, expired, revoked, or mismatched refresh material.
	ErrInvalidGrant = errors.New("invalid grant")
	// ErrRefreshReplay identifies reuse of a consumed token whose family has been compromised.
	ErrRefreshReplay = errors.New("refresh token replay")
	// ErrRefreshBusy identifies a refresh family currently processed by another request.
	ErrRefreshBusy = errors.New("refresh token is being processed")
	// ErrRefreshCollision identifies a generated handle that already exists.
	ErrRefreshCollision = errors.New("refresh token handle collision")
	// ErrCredentialIndeterminate identifies a claim that expired after upstream rotation began.
	ErrCredentialIndeterminate = errors.New("upstream credential is indeterminate")
)

// RefreshMaterial is the parsed canonical split-secret refresh token.
type RefreshMaterial struct {
	Token      string
	Handle     [16]byte
	Secret     [32]byte
	HandleHash [32]byte
	TokenHash  [32]byte
}

// RefreshGrant is the durable downstream refresh family metadata.
type RefreshGrant struct {
	SID                       string
	ClientID                  string
	Email                     string
	EmailVerified             bool
	Scopes                    string
	ConnectorID               string
	UpstreamSubject           string
	Mode                      string
	AuthTime                  time.Time
	IdleTTL                   time.Duration
	AbsoluteExpiry            time.Time
	CredentialNonce           []byte
	CredentialCiphertext      []byte
	UpstreamAccessExpiry      time.Time
	UpstreamRefreshExpiry     time.Time
	UpstreamAccessNonExpiring bool
	DPoPJKT                   string
}

// RefreshClaim fences one connector-backed refresh operation.
type RefreshClaim struct {
	ID        string
	ExpiresAt time.Time
}

// AuthCodeBinding contains the request values revalidated during code consumption.
type AuthCodeBinding struct {
	ClientID, RedirectURI, CodeChallenge string
}

// nullableTime preserves unknown upstream expiry as SQL NULL.
func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

// lockRefreshParent discovers a token's family and locks its grant before child rows.
func (s *Store) lockRefreshParent(tx *transaction, handleHash []byte) (string, error) {
	query := `SELECT g.sid FROM {{state}}refresh_grants g JOIN {{state}}refresh_tokens t ON t.sid=g.sid WHERE t.handle_hash=$1`
	if s.postgresql {
		query += ` FOR UPDATE OF g`
	}
	var sid string
	if err := tx.QueryRow(query, handleHash).Scan(&sid); err != nil {
		return "", err
	}
	return sid, nil
}

// ClaimRefresh verifies a complete token and durably claims its active grant.
func (s *Store) ClaimRefresh(current RefreshMaterial, clientID string, now time.Time, ttl time.Duration) (RefreshGrant, RefreshClaim, time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("begin refresh claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = s.lockRefreshParent(tx, current.HandleHash[:]); err == sql.ErrNoRows {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, ErrInvalidGrant
	} else if err != nil {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("lock refresh grant: %w", err)
	}
	var grant RefreshGrant
	var stored []byte
	var consumed, revoked, claimExpiry sql.NullTime
	var tokenExpiry, idleExpiry time.Time
	var claimID sql.NullString
	var started bool
	var upstreamAccess, upstreamRefresh sql.NullTime
	err = tx.QueryRow(`SELECT t.token_hash,t.consumed_at,t.expires_at,g.sid,g.client_id,g.email,g.email_verified,g.scopes,COALESCE(g.connector_id,''),COALESCE(g.upstream_subject,''),g.mode,g.auth_time,g.idle_ttl_ns,g.idle_expires_at,g.absolute_expires_at,g.revoked_at,g.credential_nonce,g.credential_ciphertext,g.claim_id,g.claim_expires_at,g.upstream_refresh_started,g.upstream_access_expires_at,g.upstream_refresh_expires_at,g.upstream_access_nonexpiring,COALESCE(g.dpop_jkt,'') FROM {{state}}refresh_tokens t JOIN {{state}}refresh_grants g ON g.sid=t.sid WHERE t.handle_hash=$1`+s.lockJoinedRows(), current.HandleHash[:]).Scan(&stored, &consumed, &tokenExpiry, &grant.SID, &grant.ClientID, &grant.Email, &grant.EmailVerified, &grant.Scopes, &grant.ConnectorID, &grant.UpstreamSubject, &grant.Mode, &grant.AuthTime, &grant.IdleTTL, &idleExpiry, &grant.AbsoluteExpiry, &revoked, &grant.CredentialNonce, &grant.CredentialCiphertext, &claimID, &claimExpiry, &started, &upstreamAccess, &upstreamRefresh, &grant.UpstreamAccessNonExpiring, &grant.DPoPJKT)
	if err == sql.ErrNoRows {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, ErrInvalidGrant
	}
	if err != nil {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("load refresh claim: %w", err)
	}
	grant.UpstreamAccessExpiry, grant.UpstreamRefreshExpiry = upstreamAccess.Time, upstreamRefresh.Time
	if subtle.ConstantTimeCompare(stored, current.TokenHash[:]) != 1 || grant.ClientID != clientID || revoked.Valid {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, ErrInvalidGrant
	}
	if consumed.Valid {
		if _, err = tx.Exec(`UPDATE {{state}}refresh_grants SET revoked_at=$1,revoke_reason='replay',claim_id=NULL,claim_expires_at=NULL,upstream_refresh_started=FALSE WHERE sid=$2 AND revoked_at IS NULL`, now, grant.SID); err != nil {
			return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("revoke claimed replay: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("commit claimed replay: %w", err)
		}
		return grant, RefreshClaim{}, time.Time{}, ErrRefreshReplay
	}
	if !now.Before(tokenExpiry) || !now.Before(idleExpiry) || !now.Before(grant.AbsoluteExpiry) {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, ErrInvalidGrant
	}
	if claimExpiry.Valid && now.Before(claimExpiry.Time) {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, ErrRefreshBusy
	}
	if claimExpiry.Valid && started {
		if _, err = tx.Exec(`UPDATE {{state}}refresh_grants SET revoked_at=$1,revoke_reason='indeterminate_upstream_credential',claim_id=NULL,claim_expires_at=NULL WHERE sid=$2 AND revoked_at IS NULL`, now, grant.SID); err != nil {
			return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("fence indeterminate credential: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("commit indeterminate credential: %w", err)
		}
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, ErrCredentialIndeterminate
	}
	id, err := GenerateStateToken()
	if err != nil {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, err
	}
	claim := RefreshClaim{ID: id, ExpiresAt: now.Add(ttl)}
	if _, err = tx.Exec(`UPDATE {{state}}refresh_grants SET claim_id=$1,claim_expires_at=$2,upstream_refresh_started=FALSE WHERE sid=$3`, claim.ID, claim.ExpiresAt, grant.SID); err != nil {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("save refresh claim: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return RefreshGrant{}, RefreshClaim{}, time.Time{}, fmt.Errorf("commit refresh claim: %w", err)
	}
	newExpiry := now.Add(grant.IdleTTL)
	if newExpiry.After(grant.AbsoluteExpiry) {
		newExpiry = grant.AbsoluteExpiry
	}
	return grant, claim, newExpiry, nil
}

// MarkUpstreamRefreshStarted durably records that provider rotation may occur.
func (s *Store) MarkUpstreamRefreshStarted(sid string, claim RefreshClaim, now time.Time) error {
	r, err := s.db.Exec(`UPDATE {{state}}refresh_grants SET upstream_refresh_started=TRUE WHERE sid=$1 AND claim_id=$2 AND claim_expires_at>$3 AND revoked_at IS NULL`, sid, claim.ID, now)
	if err != nil {
		return fmt.Errorf("mark upstream refresh started: %w", err)
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrCredentialIndeterminate
	}
	return nil
}

// ReleaseRefreshClaim releases a claim only when upstream rotation has not started.
func (s *Store) ReleaseRefreshClaim(sid string, claim RefreshClaim) error {
	_, err := s.db.Exec(`UPDATE {{state}}refresh_grants SET claim_id=NULL,claim_expires_at=NULL,upstream_refresh_started=FALSE WHERE sid=$1 AND claim_id=$2 AND upstream_refresh_started=FALSE`, sid, claim.ID)
	if err != nil {
		return fmt.Errorf("release refresh claim: %w", err)
	}
	return nil
}

// AbortUpstreamRefresh releases a claim after a definitive provider response proves no rotation occurred.
func (s *Store) AbortUpstreamRefresh(sid string, claim RefreshClaim) error {
	r, err := s.db.Exec(`UPDATE {{state}}refresh_grants SET claim_id=NULL,claim_expires_at=NULL,upstream_refresh_started=FALSE WHERE sid=$1 AND claim_id=$2 AND revoked_at IS NULL`, sid, claim.ID)
	if err != nil {
		return fmt.Errorf("abort upstream refresh: %w", err)
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrCredentialIndeterminate
	}
	return nil
}

// CompleteClaimedRefresh conditionally rotates a claimed token and replaces its encrypted credential.
func (s *Store) CompleteClaimedRefresh(current, replacement RefreshMaterial, grant RefreshGrant, claim RefreshClaim, nonce, ciphertext []byte, absoluteExpiry, now time.Time) (time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return time.Time{}, fmt.Errorf("begin claimed refresh: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = s.lockRefreshParent(tx, current.HandleHash[:]); err == sql.ErrNoRows {
		return time.Time{}, ErrInvalidGrant
	} else if err != nil {
		return time.Time{}, fmt.Errorf("lock claimed refresh grant: %w", err)
	}
	var tokenExpiry, idleExpiry, storedAbsolute time.Time
	if err = tx.QueryRow(`SELECT t.expires_at,g.idle_expires_at,g.absolute_expires_at FROM {{state}}refresh_tokens t JOIN {{state}}refresh_grants g ON g.sid=t.sid WHERE t.handle_hash=$1 AND t.token_hash=$2 AND t.consumed_at IS NULL AND g.sid=$3 AND g.claim_id=$4 AND g.revoked_at IS NULL`+s.lockJoinedRows(), current.HandleHash[:], current.TokenHash[:], grant.SID, claim.ID).Scan(&tokenExpiry, &idleExpiry, &storedAbsolute); err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, ErrInvalidGrant
		}
		return time.Time{}, fmt.Errorf("recheck claimed refresh: %w", err)
	}
	if !now.Before(tokenExpiry) || !now.Before(idleExpiry) || !now.Before(storedAbsolute) {
		return time.Time{}, ErrInvalidGrant
	}
	newExpiry := now.Add(grant.IdleTTL)
	if absoluteExpiry.After(storedAbsolute) {
		absoluteExpiry = storedAbsolute
	}
	if newExpiry.After(absoluteExpiry) {
		newExpiry = absoluteExpiry
	}
	r, err := tx.Exec(`UPDATE {{state}}refresh_tokens SET consumed_at=$1,replacement_hash=$2 WHERE handle_hash=$3 AND token_hash=$4 AND consumed_at IS NULL AND sid=$5`, now, replacement.TokenHash[:], current.HandleHash[:], current.TokenHash[:], grant.SID)
	if err != nil {
		return time.Time{}, fmt.Errorf("consume claimed token: %w", err)
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return time.Time{}, ErrInvalidGrant
	}
	r, err = tx.Exec(`UPDATE {{state}}refresh_grants SET credential_nonce=$1,credential_ciphertext=$2,absolute_expires_at=$3,upstream_access_expires_at=$4,upstream_refresh_expires_at=$5,upstream_access_nonexpiring=$6,last_used_at=$7,idle_expires_at=$8,claim_id=NULL,claim_expires_at=NULL,upstream_refresh_started=FALSE WHERE sid=$9 AND claim_id=$10 AND claim_expires_at>$11 AND revoked_at IS NULL`, nonce, ciphertext, absoluteExpiry, nullableTime(grant.UpstreamAccessExpiry), nullableTime(grant.UpstreamRefreshExpiry), grant.UpstreamAccessNonExpiring, now, newExpiry, grant.SID, claim.ID, now)
	if err != nil {
		return time.Time{}, fmt.Errorf("update claimed grant: %w", err)
	}
	n, _ = r.RowsAffected()
	if n != 1 {
		return time.Time{}, ErrCredentialIndeterminate
	}
	if err = insertRefreshToken(tx, replacement, grant.SID, now, newExpiry); err != nil {
		return time.Time{}, err
	}
	if err = tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit claimed refresh: %w", err)
	}
	return newExpiry, nil
}

// ConsumeAuthCode atomically verifies and consumes an unchanged code and optionally creates its initial refresh grant.
func (s *Store) ConsumeAuthCode(expected AuthCode, binding AuthCodeBinding, grant *RefreshGrant, material RefreshMaterial, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin code exchange: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var actual AuthCode
	err = tx.QueryRow(`SELECT code,client_id,redirect_uri,code_challenge,email,email_verified,nonce,created_at,expires_at,scopes,refresh_mode,auth_time,connector_id,upstream_subject,offline_consent,COALESCE(dpop_jkt,''),pushed_authorization FROM {{state}}auth_codes WHERE code=$1`+s.lockRows(), expected.Code).Scan(&actual.Code, &actual.ClientID, &actual.RedirectURI, &actual.CodeChallenge, &actual.Email, &actual.EmailVerified, &actual.Nonce, &actual.CreatedAt, &actual.ExpiresAt, &actual.Scopes, &actual.RefreshMode, &actual.AuthTime, &actual.ConnectorID, &actual.UpstreamSubject, &actual.OfflineConsent, &actual.DPoPJKT, &actual.PushedAuthorization)
	if err == sql.ErrNoRows {
		return ErrInvalidGrant
	}
	if err != nil {
		return fmt.Errorf("reread authorization code: %w", err)
	}
	if actual != expected || actual.ClientID != binding.ClientID || actual.RedirectURI != binding.RedirectURI || actual.CodeChallenge != binding.CodeChallenge || !now.Before(actual.ExpiresAt) {
		return ErrInvalidGrant
	}
	result, err := tx.Exec(`DELETE FROM {{state}}auth_codes WHERE code=$1`, expected.Code)
	if err != nil {
		return fmt.Errorf("consume authorization code: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return ErrInvalidGrant
	}
	if grant != nil {
		expires := now.Add(grant.IdleTTL)
		if expires.After(grant.AbsoluteExpiry) {
			expires = grant.AbsoluteExpiry
		}
		_, err = tx.Exec(`INSERT INTO {{state}}refresh_grants(sid,client_id,email,email_verified,scopes,connector_id,upstream_subject,credential_nonce,credential_ciphertext,mode,auth_time,created_at,last_used_at,idle_ttl_ns,idle_expires_at,absolute_expires_at,upstream_access_expires_at,upstream_refresh_expires_at,upstream_access_nonexpiring,dpop_jkt) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, grant.SID, grant.ClientID, strings.ToLower(grant.Email), grant.EmailVerified, grant.Scopes, grant.ConnectorID, grant.UpstreamSubject, grant.CredentialNonce, grant.CredentialCiphertext, grant.Mode, grant.AuthTime, now, now, int64(grant.IdleTTL), expires, grant.AbsoluteExpiry, nullableTime(grant.UpstreamAccessExpiry), nullableTime(grant.UpstreamRefreshExpiry), grant.UpstreamAccessNonExpiring, nullable(grant.DPoPJKT))
		if err == nil {
			err = insertRefreshToken(tx, material, grant.SID, now, expires)
		}
		if err != nil {
			if errors.Is(err, ErrRefreshCollision) {
				return err
			}
			return fmt.Errorf("create initial refresh grant: %w", err)
		}
		if grant.ConnectorID != "" && len(grant.CredentialCiphertext) != 0 {
			if _, err = tx.Exec(`DELETE FROM {{state}}flow_credentials WHERE flow_id=$1`, expected.Code); err != nil {
				return fmt.Errorf("delete temporary credential: %w", err)
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit code exchange: %w", err)
	}
	return nil
}

// PrepareRefresh verifies refresh material without consuming it and returns its current grant and token expiry.
func (s *Store) PrepareRefresh(current RefreshMaterial, clientID string, now time.Time) (RefreshGrant, time.Time, error) {
	var grant RefreshGrant
	var storedHash []byte
	var consumed, revoked sql.NullTime
	var upstreamAccess, upstreamRefresh sql.NullTime
	var tokenExpiry, idleExpiry time.Time
	err := s.db.QueryRow(`SELECT t.token_hash,t.consumed_at,t.expires_at,g.sid,g.client_id,g.email,g.email_verified,g.scopes,COALESCE(g.connector_id,''),COALESCE(g.upstream_subject,''),g.mode,g.auth_time,g.idle_ttl_ns,g.idle_expires_at,g.absolute_expires_at,g.revoked_at,g.credential_nonce,g.credential_ciphertext,g.upstream_access_expires_at,g.upstream_refresh_expires_at,g.upstream_access_nonexpiring,COALESCE(g.dpop_jkt,'') FROM {{state}}refresh_tokens t JOIN {{state}}refresh_grants g ON g.sid=t.sid WHERE t.handle_hash=$1`, current.HandleHash[:]).Scan(&storedHash, &consumed, &tokenExpiry, &grant.SID, &grant.ClientID, &grant.Email, &grant.EmailVerified, &grant.Scopes, &grant.ConnectorID, &grant.UpstreamSubject, &grant.Mode, &grant.AuthTime, &grant.IdleTTL, &idleExpiry, &grant.AbsoluteExpiry, &revoked, &grant.CredentialNonce, &grant.CredentialCiphertext, &upstreamAccess, &upstreamRefresh, &grant.UpstreamAccessNonExpiring, &grant.DPoPJKT)
	if err == sql.ErrNoRows {
		return RefreshGrant{}, time.Time{}, ErrInvalidGrant
	}
	if err != nil {
		return RefreshGrant{}, time.Time{}, fmt.Errorf("prepare refresh: %w", err)
	}
	grant.UpstreamAccessExpiry, grant.UpstreamRefreshExpiry = upstreamAccess.Time, upstreamRefresh.Time
	if subtle.ConstantTimeCompare(storedHash, current.TokenHash[:]) != 1 || grant.ClientID != clientID || revoked.Valid {
		return RefreshGrant{}, time.Time{}, ErrInvalidGrant
	}
	if consumed.Valid {
		return grant, time.Time{}, ErrRefreshReplay
	}
	if !now.Before(tokenExpiry) || !now.Before(idleExpiry) || !now.Before(grant.AbsoluteExpiry) {
		return RefreshGrant{}, time.Time{}, ErrInvalidGrant
	}
	newExpiry := now.Add(grant.IdleTTL)
	if newExpiry.After(grant.AbsoluteExpiry) {
		newExpiry = grant.AbsoluteExpiry
	}
	return grant, newExpiry, nil
}

// GenerateRefreshMaterial creates a canonical random ert1 token.
func GenerateRefreshMaterial() (RefreshMaterial, error) {
	var material RefreshMaterial
	if _, err := rand.Read(material.Handle[:]); err != nil {
		return material, fmt.Errorf("generate refresh handle: %w", err)
	}
	if _, err := rand.Read(material.Secret[:]); err != nil {
		return material, fmt.Errorf("generate refresh secret: %w", err)
	}
	material.Token = "ert1." + base64.RawURLEncoding.EncodeToString(material.Handle[:]) + "." + base64.RawURLEncoding.EncodeToString(material.Secret[:])
	material.HandleHash = sha256.Sum256(material.Handle[:])
	material.TokenHash = sha256.Sum256([]byte(material.Token))
	return material, nil
}

// ParseRefreshToken parses and canonicality-checks an ert1 split-secret token.
func ParseRefreshToken(token string) (RefreshMaterial, error) {
	var material RefreshMaterial
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "ert1" || strings.Contains(parts[1], "=") || strings.Contains(parts[2], "=") {
		return material, ErrInvalidGrant
	}
	handle, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(handle) != len(material.Handle) {
		return material, ErrInvalidGrant
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(secret) != len(material.Secret) {
		return material, ErrInvalidGrant
	}
	if base64.RawURLEncoding.EncodeToString(handle) != parts[1] || base64.RawURLEncoding.EncodeToString(secret) != parts[2] {
		return material, ErrInvalidGrant
	}
	copy(material.Handle[:], handle)
	copy(material.Secret[:], secret)
	material.Token = token
	material.HandleHash = sha256.Sum256(handle)
	material.TokenHash = sha256.Sum256([]byte(token))
	return material, nil
}

// credentialAAD encodes unambiguous versioned and length-delimited credential context.
func credentialAAD(sid, clientID, connectorID string) []byte {
	result := []byte{1}
	for _, value := range []string{sid, clientID, connectorID} {
		result = binary.BigEndian.AppendUint32(result, uint32(len(value)))
		result = append(result, value...)
	}
	return result
}

// EncryptTemporaryCredential encrypts a flow credential with the configured master key.
func EncryptTemporaryCredential(key []byte, flowID, clientID, connectorID string, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create temporary credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create temporary credential AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate temporary credential nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, credentialAAD(flowID, clientID, connectorID)), nil
}

// DecryptTemporaryCredential decrypts and authenticates a flow credential.
func DecryptTemporaryCredential(key []byte, flowID, clientID, connectorID string, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create temporary credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create temporary credential AEAD: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, credentialAAD(flowID, clientID, connectorID))
	if err != nil {
		return nil, ErrInvalidGrant
	}
	return plain, nil
}

// SaveFlowCredential stores or atomically relabels an encrypted temporary credential.
func (s *Store) SaveFlowCredential(from, to, clientID, connectorID string, nonce, ciphertext []byte, expires time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin flow credential: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if from != "" {
		if _, err = tx.Exec(`DELETE FROM {{state}}flow_credentials WHERE flow_id=$1`, from); err != nil {
			return fmt.Errorf("delete predecessor credential: %w", err)
		}
	}
	query := `INSERT OR REPLACE INTO {{state}}flow_credentials(flow_id,client_id,connector_id,nonce,ciphertext,expires_at) VALUES($1,$2,$3,$4,$5,$6)`
	if s.postgresql {
		query = `INSERT INTO {{state}}flow_credentials(flow_id,client_id,connector_id,nonce,ciphertext,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(flow_id) DO UPDATE SET client_id=excluded.client_id,connector_id=excluded.connector_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext,expires_at=excluded.expires_at`
	}
	if _, err = tx.Exec(query, to, clientID, connectorID, nonce, ciphertext, expires); err != nil {
		return fmt.Errorf("save flow credential: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit flow credential: %w", err)
	}
	return nil
}

// LoadFlowCredential loads an encrypted, unexpired temporary credential.
func (s *Store) LoadFlowCredential(flowID, clientID, connectorID string, now time.Time) ([]byte, []byte, error) {
	var nonce, ciphertext []byte
	err := s.db.QueryRow(`SELECT nonce,ciphertext FROM {{state}}flow_credentials WHERE flow_id=$1 AND client_id=$2 AND connector_id=$3 AND expires_at>$4`, flowID, clientID, connectorID, now).Scan(&nonce, &ciphertext)
	if err == sql.ErrNoRows {
		return nil, nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load flow credential: %w", err)
	}
	return nonce, ciphertext, nil
}

// deriveCredentialKey derives the grant encryption key from the client-held secret.
func deriveCredentialKey(secret [32]byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, secret[:], nil, "truster upstream credential v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive credential key: %w", err)
	}
	return key, nil
}

// EncryptCredential encrypts an upstream credential using AES-256-GCM and fresh randomness.
func EncryptCredential(secret [32]byte, sid, clientID, connectorID string, plaintext []byte) ([]byte, []byte, error) {
	key, err := deriveCredentialKey(secret)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create credential AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, credentialAAD(sid, clientID, connectorID)), nil
}

// DecryptCredential authenticates and decrypts an upstream credential.
func DecryptCredential(secret [32]byte, sid, clientID, connectorID string, nonce, ciphertext []byte) ([]byte, error) {
	key, err := deriveCredentialKey(secret)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create credential AEAD: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, credentialAAD(sid, clientID, connectorID))
	if err != nil {
		return nil, ErrInvalidGrant
	}
	return plaintext, nil
}

// CreateRefreshGrant atomically creates a grant and its first token.
func (s *Store) CreateRefreshGrant(grant RefreshGrant, material RefreshMaterial, nonce, ciphertext []byte, now time.Time) error {
	expires := now.Add(grant.IdleTTL)
	if expires.After(grant.AbsoluteExpiry) {
		expires = grant.AbsoluteExpiry
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin grant creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`INSERT INTO {{state}}refresh_grants(sid,client_id,email,email_verified,scopes,connector_id,upstream_subject,credential_nonce,credential_ciphertext,mode,auth_time,created_at,last_used_at,idle_ttl_ns,idle_expires_at,absolute_expires_at,upstream_access_expires_at,upstream_refresh_expires_at,upstream_access_nonexpiring,dpop_jkt) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, grant.SID, grant.ClientID, strings.ToLower(grant.Email), grant.EmailVerified, grant.Scopes, grant.ConnectorID, grant.UpstreamSubject, nonce, ciphertext, grant.Mode, grant.AuthTime, now, now, int64(grant.IdleTTL), expires, grant.AbsoluteExpiry, nullableTime(grant.UpstreamAccessExpiry), nullableTime(grant.UpstreamRefreshExpiry), grant.UpstreamAccessNonExpiring, nullable(grant.DPoPJKT))
	if err == nil {
		err = insertRefreshToken(tx, material, grant.SID, now, expires)
	}
	if err != nil {
		if errors.Is(err, ErrRefreshCollision) {
			return err
		}
		return fmt.Errorf("create refresh grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit refresh grant: %w", err)
	}
	return nil
}

// RotateRefreshToken atomically consumes a token, installs its replacement, and revokes replayed families.
func (s *Store) RotateRefreshToken(current, replacement RefreshMaterial, clientID string, now time.Time) (RefreshGrant, time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return RefreshGrant{}, time.Time{}, fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = s.lockRefreshParent(tx, current.HandleHash[:]); err == sql.ErrNoRows {
		return RefreshGrant{}, time.Time{}, ErrInvalidGrant
	} else if err != nil {
		return RefreshGrant{}, time.Time{}, fmt.Errorf("lock refresh grant: %w", err)
	}
	var grant RefreshGrant
	var storedHash []byte
	var consumed sql.NullTime
	var tokenExpiry, idleExpiry time.Time
	var revoked sql.NullTime
	err = tx.QueryRow(`SELECT t.token_hash,t.consumed_at,t.expires_at,g.sid,g.client_id,g.email,g.email_verified,g.scopes,COALESCE(g.connector_id,''),COALESCE(g.upstream_subject,''),g.mode,g.auth_time,g.idle_ttl_ns,g.idle_expires_at,g.absolute_expires_at,g.revoked_at FROM {{state}}refresh_tokens t JOIN {{state}}refresh_grants g ON g.sid=t.sid WHERE t.handle_hash=$1`+s.lockJoinedRows(), current.HandleHash[:]).Scan(&storedHash, &consumed, &tokenExpiry, &grant.SID, &grant.ClientID, &grant.Email, &grant.EmailVerified, &grant.Scopes, &grant.ConnectorID, &grant.UpstreamSubject, &grant.Mode, &grant.AuthTime, &grant.IdleTTL, &idleExpiry, &grant.AbsoluteExpiry, &revoked)
	if err == sql.ErrNoRows {
		return RefreshGrant{}, time.Time{}, ErrInvalidGrant
	}
	if err != nil {
		return RefreshGrant{}, time.Time{}, fmt.Errorf("lookup refresh token: %w", err)
	}
	if subtle.ConstantTimeCompare(storedHash, current.TokenHash[:]) != 1 || grant.ClientID != clientID || revoked.Valid {
		return RefreshGrant{}, time.Time{}, ErrInvalidGrant
	}
	if consumed.Valid {
		if _, err := tx.Exec(`UPDATE {{state}}refresh_grants SET revoked_at=$1,revoke_reason='replay' WHERE sid=$2 AND revoked_at IS NULL`, now, grant.SID); err != nil {
			return RefreshGrant{}, time.Time{}, fmt.Errorf("revoke replayed grant: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return RefreshGrant{}, time.Time{}, fmt.Errorf("commit replay revocation: %w", err)
		}
		return RefreshGrant{}, time.Time{}, ErrRefreshReplay
	}
	if !now.Before(tokenExpiry) || !now.Before(idleExpiry) || !now.Before(grant.AbsoluteExpiry) {
		return RefreshGrant{}, time.Time{}, ErrInvalidGrant
	}
	newExpiry := now.Add(grant.IdleTTL)
	if newExpiry.After(grant.AbsoluteExpiry) {
		newExpiry = grant.AbsoluteExpiry
	}
	result, err := tx.Exec(`UPDATE {{state}}refresh_tokens SET consumed_at=$1,replacement_hash=$2 WHERE handle_hash=$3 AND consumed_at IS NULL`, now, replacement.TokenHash[:], current.HandleHash[:])
	if err != nil {
		return RefreshGrant{}, time.Time{}, fmt.Errorf("consume refresh token: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		// An authenticated conditional miss is replay. Commit the family
		// revocation rather than rolling it back with this transaction.
		if _, err = tx.Exec(`UPDATE {{state}}refresh_grants SET revoked_at=$1,revoke_reason='replay' WHERE sid=$2 AND revoked_at IS NULL`, now, grant.SID); err != nil {
			return RefreshGrant{}, time.Time{}, fmt.Errorf("revoke raced replay: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return RefreshGrant{}, time.Time{}, fmt.Errorf("commit raced replay revocation: %w", err)
		}
		return RefreshGrant{}, time.Time{}, ErrRefreshReplay
	}
	if err = insertRefreshToken(tx, replacement, grant.SID, now, newExpiry); err != nil {
		return RefreshGrant{}, time.Time{}, err
	}
	if _, err = tx.Exec(`UPDATE {{state}}refresh_grants SET last_used_at=$1,idle_expires_at=$2 WHERE sid=$3`, now, newExpiry, grant.SID); err != nil {
		return RefreshGrant{}, time.Time{}, fmt.Errorf("update refresh grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RefreshGrant{}, time.Time{}, fmt.Errorf("commit refresh rotation: %w", err)
	}
	return grant, newExpiry, nil
}

// insertRefreshToken reports generated handle collisions separately from storage failures.
func insertRefreshToken(tx *transaction, material RefreshMaterial, sid string, issued, expires time.Time) error {
	result, err := tx.Exec(`INSERT INTO {{state}}refresh_tokens(handle_hash,token_hash,sid,issued_at,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(handle_hash) DO NOTHING`, material.HandleHash[:], material.TokenHash[:], sid, issued, expires)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect refresh token insert: %w", err)
	}
	if affected != 1 {
		return ErrRefreshCollision
	}
	return nil
}

// RevokeGrant revokes an active refresh family identified by sid and client.
func (s *Store) RevokeGrant(sid, clientID, reason string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE {{state}}refresh_grants SET revoked_at=$1,revoke_reason=$2 WHERE sid=$3 AND client_id=$4 AND revoked_at IS NULL`, now, reason, sid, clientID)
	if err != nil {
		return fmt.Errorf("revoke refresh grant: %w", err)
	}
	return nil
}

// RevokeRefreshToken revokes a known refresh family only when it belongs to clientID.
func (s *Store) RevokeRefreshToken(material RefreshMaterial, clientID, reason string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE {{state}}refresh_grants SET revoked_at=$1,revoke_reason=$2 WHERE sid=(SELECT sid FROM {{state}}refresh_tokens WHERE handle_hash=$3 AND token_hash=$4) AND client_id=$5 AND revoked_at IS NULL`, now, reason, material.HandleHash[:], material.TokenHash[:], clientID)
	if err != nil {
		return fmt.Errorf("revoke refresh grant: %w", err)
	}
	return nil
}
