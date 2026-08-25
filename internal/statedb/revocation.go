// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"database/sql"
	"fmt"
	"time"
)

// RevocationCredential identifies a submitted credential without granting endpoint code direct state access.
type RevocationCredential struct {
	Refresh             *RefreshMaterial
	SID                 string
	TokenJKT            string
	RequireTokenBinding bool
}

// RevokeCredential conditionally revokes an active credential without reserving a proof.
func (s *Store) RevokeCredential(credential RevocationCredential, clientID, proofJKT, reason string, now time.Time) error {
	now = now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin credential revocation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var sid, grantJKT string
	var tokenExpiry, idleExpiry, absoluteExpiry time.Time
	var consumed, revoked sql.NullTime
	if credential.Refresh != nil {
		err = tx.QueryRow(`SELECT g.sid,COALESCE(g.dpop_jkt,''),t.expires_at,g.idle_expires_at,g.absolute_expires_at,t.consumed_at,g.revoked_at FROM {{state}}refresh_tokens t JOIN {{state}}refresh_grants g ON g.sid=t.sid WHERE t.handle_hash=$1 AND t.token_hash=$2 AND g.client_id=$3`+s.lockJoinedRows(), credential.Refresh.HandleHash[:], credential.Refresh.TokenHash[:], clientID).Scan(&sid, &grantJKT, &tokenExpiry, &idleExpiry, &absoluteExpiry, &consumed, &revoked)
	} else if credential.SID != "" {
		err = tx.QueryRow(`SELECT sid,COALESCE(dpop_jkt,''),idle_expires_at,absolute_expires_at,revoked_at FROM {{state}}refresh_grants WHERE sid=$1 AND client_id=$2`+s.lockRows(), credential.SID, clientID).Scan(&sid, &grantJKT, &idleExpiry, &absoluteExpiry, &revoked)
	} else {
		err = sql.ErrNoRows
	}
	usable := err == nil && !revoked.Valid && !consumed.Valid && now.Before(idleExpiry) && now.Before(absoluteExpiry) && (credential.Refresh == nil || now.Before(tokenExpiry))
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("inspect revocation credential: %w", err)
	}
	if usable {
		matches := false
		if proofJKT == "" {
			matches = grantJKT == "" && credential.TokenJKT == ""
		} else if grantJKT != "" && proofJKT == grantJKT {
			matches = credential.Refresh != nil || !credential.RequireTokenBinding || credential.TokenJKT == grantJKT
		}
		if matches {
			if _, err = tx.Exec(`UPDATE {{state}}refresh_grants SET revoked_at=$1,revoke_reason=$2 WHERE sid=$3 AND revoked_at IS NULL`, now, reason, sid); err != nil {
				return fmt.Errorf("revoke credential grant: %w", err)
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit credential revocation: %w", err)
	}
	return nil
}
