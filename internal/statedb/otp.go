// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// OTPFlow preserves the authorization and identity context of an OTP challenge.
type OTPFlow struct {
	FlowID              string
	ConnectorID         string
	Subject             string
	Email               string
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

// OTPResendError describes a rejected resend and how long a caller should wait before retrying.
type OTPResendError struct {
	RetryAfter time.Duration
}

// Error returns a client-safe resend rejection message.
func (*OTPResendError) Error() string { return "resend unavailable" }

// otpMAC authenticates a code while binding it to its challenge.
func otpMAC(secret []byte, challengeID, code string) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(challengeID + "\x00" + code))
	return h.Sum(nil)
}

// CreateOTP atomically enforces the address-only hourly quota, creates a challenge, and returns its expiry.
func (s *Store) CreateOTP(challengeID, email, code string, flow OTPFlow, secret []byte, now time.Time, ttl time.Duration) (time.Time, error) {
	email = strings.ToLower(email)
	expiresAt := now.Add(ttl)
	context, err := json.Marshal(flow)
	if err != nil {
		return time.Time{}, fmt.Errorf("encode OTP flow: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if s.postgresql {
		if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err != nil {
			return time.Time{}, fmt.Errorf("lock OTP quota: %w", err)
		}
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM {{state}}otp_sends WHERE email=$1 AND sent_at>$2`, email, now.Add(-time.Hour)).Scan(&count); err != nil {
		return time.Time{}, err
	}
	if count >= 5 {
		return time.Time{}, fmt.Errorf("email send limit exceeded")
	}
	_, err = tx.Exec(`INSERT INTO {{state}}otp_challenges(challenge_id,email,code_hmac,context,created_at,sent_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, challengeID, email, otpMAC(secret, challengeID, code), string(context), now, now, expiresAt)
	if err != nil {
		return time.Time{}, err
	}
	if _, err = tx.Exec(`INSERT INTO {{state}}otp_sends(email,sent_at) VALUES($1,$2)`, email, now); err != nil {
		return time.Time{}, err
	}
	return expiresAt, tx.Commit()
}

// ResendOTP replaces an active challenge's code and returns its flow and new expiry without reviving dead challenges.
func (s *Store) ResendOTP(challengeID, code string, secret []byte, now time.Time, ttl time.Duration) (OTPFlow, time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return OTPFlow{}, time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var email string
	var context []byte
	var sentAt, expiresAt time.Time
	if err = tx.QueryRow(`SELECT email,context,sent_at,expires_at FROM {{state}}otp_challenges WHERE challenge_id=$1`+s.lockRows(), challengeID).Scan(&email, &context, &sentAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OTPFlow{}, time.Time{}, &OTPResendError{}
		}
		return OTPFlow{}, time.Time{}, err
	}
	var flow OTPFlow
	if err = json.Unmarshal(context, &flow); err != nil {
		return OTPFlow{}, time.Time{}, fmt.Errorf("decode OTP flow: %w", err)
	}
	if !now.Before(expiresAt) {
		return flow, time.Time{}, &OTPResendError{}
	}
	if retryAfter := sentAt.Add(time.Minute).Sub(now); retryAfter > 0 {
		return flow, time.Time{}, &OTPResendError{RetryAfter: retryAfter}
	}
	if s.postgresql {
		if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err != nil {
			return OTPFlow{}, time.Time{}, fmt.Errorf("lock OTP quota: %w", err)
		}
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM {{state}}otp_sends WHERE email=$1 AND sent_at>$2`, email, now.Add(-time.Hour)).Scan(&count); err != nil {
		return OTPFlow{}, time.Time{}, err
	}
	if count >= 5 {
		var oldest time.Time
		if err = tx.QueryRow(`SELECT sent_at FROM {{state}}otp_sends WHERE email=$1 AND sent_at>$2 ORDER BY sent_at LIMIT 1`, email, now.Add(-time.Hour)).Scan(&oldest); err != nil {
			return OTPFlow{}, time.Time{}, err
		}
		return flow, time.Time{}, &OTPResendError{RetryAfter: oldest.Add(time.Hour).Sub(now)}
	}
	newExpiresAt := now.Add(ttl)
	result, err := tx.Exec(`UPDATE {{state}}otp_challenges SET code_hmac=$1,attempts=0,sends=sends+1,sent_at=$2,expires_at=$3 WHERE challenge_id=$4 AND sent_at=$5 AND expires_at>$6`, otpMAC(secret, challengeID, code), now, newExpiresAt, challengeID, sentAt, now)
	if err != nil {
		return OTPFlow{}, time.Time{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		if rowsErr != nil {
			return OTPFlow{}, time.Time{}, rowsErr
		}
		return flow, time.Time{}, &OTPResendError{RetryAfter: time.Minute}
	}
	if _, err = tx.Exec(`INSERT INTO {{state}}otp_sends(email,sent_at) VALUES($1,$2)`, email, now); err != nil {
		return OTPFlow{}, time.Time{}, err
	}
	if err = tx.Commit(); err != nil {
		return OTPFlow{}, time.Time{}, err
	}
	return flow, newExpiresAt, nil
}

// OTPFlow retrieves the authorization context for an active challenge.
func (s *Store) OTPFlow(challengeID string) (OTPFlow, error) {
	var raw []byte
	if err := s.db.QueryRow(`SELECT context FROM {{state}}otp_challenges WHERE challenge_id=$1`, challengeID).Scan(&raw); err != nil {
		return OTPFlow{}, fmt.Errorf("invalid challenge")
	}
	var flow OTPFlow
	if err := json.Unmarshal(raw, &flow); err != nil {
		return OTPFlow{}, fmt.Errorf("decode OTP flow: %w", err)
	}
	return flow, nil
}

// ConsumeOTP atomically limits attempts and makes successful codes single-use.
func (s *Store) ConsumeOTP(challengeID, code string, secret []byte, now time.Time) (OTPFlow, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return OTPFlow{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var mac []byte
	var context []byte
	var attempts int
	var expires time.Time
	if err = tx.QueryRow(`SELECT code_hmac,context,attempts,expires_at FROM {{state}}otp_challenges WHERE challenge_id=$1`+s.lockRows(), challengeID).Scan(&mac, &context, &attempts, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OTPFlow{}, fmt.Errorf("invalid challenge")
		}
		return OTPFlow{}, fmt.Errorf("load OTP challenge: %w", err)
	}
	if !now.Before(expires) || attempts >= 5 {
		return OTPFlow{}, fmt.Errorf("invalid challenge")
	}
	if !hmac.Equal(mac, otpMAC(secret, challengeID, code)) {
		result, updateErr := tx.Exec(`UPDATE {{state}}otp_challenges SET attempts=attempts+1 WHERE challenge_id=$1 AND attempts=$2`, challengeID, attempts)
		if updateErr != nil {
			return OTPFlow{}, updateErr
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
			return OTPFlow{}, fmt.Errorf("invalid challenge")
		}
		if err = tx.Commit(); err != nil {
			return OTPFlow{}, err
		}
		return OTPFlow{}, fmt.Errorf("invalid code")
	}
	var flow OTPFlow
	if err = json.Unmarshal(context, &flow); err != nil {
		return OTPFlow{}, fmt.Errorf("decode OTP flow: %w", err)
	}
	result, err := tx.Exec(`DELETE FROM {{state}}otp_challenges WHERE challenge_id=$1 AND attempts=$2`, challengeID, attempts)
	if err != nil {
		return OTPFlow{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return OTPFlow{}, fmt.Errorf("invalid challenge")
	}
	if err = tx.Commit(); err != nil {
		return OTPFlow{}, err
	}
	return flow, nil
}
