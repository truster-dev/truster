// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SavePushedRequest persists a bounded-lifetime pushed authorization request.
func (s *Store) SavePushedRequest(p *PushedRequest) error {
	_, err := s.db.Exec(`INSERT INTO {{state}}pushed_requests(request_uri,client_id,redirect_uri,response_type,scopes,oidc_state,nonce,code_challenge,code_challenge_method,prompt,dpop_jkt,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, p.RequestURI, p.ClientID, p.RedirectURI, p.ResponseType, p.Scopes, p.State, p.Nonce, p.CodeChallenge, p.CodeChallengeMethod, p.Prompt, nullable(p.DPoPJKT), p.CreatedAt, p.ExpiresAt)
	if err != nil {
		return fmt.Errorf("save pushed request: %w", err)
	}
	return nil
}

// ConsumePushedRequest deletes and returns one client-bound, unexpired request.
func (s *Store) ConsumePushedRequest(requestURI, clientID string, now time.Time) (*PushedRequest, error) {
	var p PushedRequest
	err := s.db.QueryRow(`DELETE FROM {{state}}pushed_requests WHERE request_uri=$1 AND client_id=$2 AND expires_at>$3 RETURNING client_id,redirect_uri,response_type,scopes,oidc_state,COALESCE(nonce,''),code_challenge,code_challenge_method,COALESCE(prompt,''),COALESCE(dpop_jkt,''),created_at,expires_at`, requestURI, clientID, now.UTC()).Scan(&p.ClientID, &p.RedirectURI, &p.ResponseType, &p.Scopes, &p.State, &p.Nonce, &p.CodeChallenge, &p.CodeChallengeMethod, &p.Prompt, &p.DPoPJKT, &p.CreatedAt, &p.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("consume pushed request: %w", err)
	}
	p.RequestURI = requestURI
	return &p, nil
}

// cleanupPARRequests removes a bounded batch of expired pushed authorization requests.
func (s *Store) cleanupPARRequests(now time.Time) error {
	query := `DELETE FROM {{state}}pushed_requests WHERE request_uri IN (SELECT request_uri FROM {{state}}pushed_requests WHERE expires_at < $1 LIMIT 500)`
	if s.postgresql {
		query = `DELETE FROM {{state}}pushed_requests WHERE ctid IN (SELECT ctid FROM {{state}}pushed_requests WHERE expires_at < $1 LIMIT 500 FOR UPDATE SKIP LOCKED)`
	}
	_, err := s.db.Exec(query, now.UTC())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("clean PAR requests: %w", err)
	}
	return nil
}
