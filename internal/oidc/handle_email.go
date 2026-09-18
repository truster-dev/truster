// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
)

// otpCode generates an eight-digit cryptographically random code.
func otpCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

// normalizeEmail validates and lowercases a bare email address.
func normalizeEmail(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized {
		return "", fmt.Errorf("invalid email address")
	}
	return normalized, nil
}

// HandleEmailStart validates an email sign-in request and begins OTP verification.
func (s *Server) HandleEmailStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !parseBrowserForm(w, r, "state", "connector", "cf-turnstile-response", "email") {
		return
	}
	state, err := s.authCodeMgr.DecodeState(r.PostForm.Get("state"))
	if err != nil || state.ConnectorID != "" {
		http.Error(w, "invalid state", 400)
		return
	}
	connectorID := r.PostForm.Get("connector")
	connector, ok := s.config.UserLoginConnectors[connectorID]
	if !ok || connector.Type != "email" {
		http.Error(w, "invalid connector", 400)
		return
	}
	state.ConnectorID = connectorID
	remoteIP := ""
	if s.config.Email != nil && s.config.Email.Turnstile != nil && s.config.Email.Turnstile.RemoteIP != nil {
		remoteIP = remoteIPFromRequest(r, s.config.Email.Turnstile.RemoteIP.Source, s.config.Email.Turnstile.RemoteIP.Header)
	}
	if err = s.challenge.Verify(r.Context(), r.PostForm.Get("cf-turnstile-response"), remoteIP); err != nil {
		s.logger.Warn("reject email challenge", "error", err)
		s.renderErrorPage(w, http.StatusBadRequest, "Security check failed", "We couldn't verify the security check. Return to sign in and try again.")
		return
	}
	email, err := normalizeEmail(r.PostForm.Get("email"))
	if err != nil {
		http.Error(w, "invalid email", 400)
		return
	}
	s.beginOTP(w, r, *state, connectorID, email, email)
}

// remoteIPFromRequest returns a valid IP from the explicitly configured request source.
func remoteIPFromRequest(r *http.Request, source, header string) string {
	value := ""
	switch source {
	case "remote_addr":
		value = r.RemoteAddr
		if host, _, err := net.SplitHostPort(value); err == nil {
			value = host
		}
	case "header":
		value = strings.TrimSpace(strings.Split(r.Header.Get(header), ",")[0])
	}
	if net.ParseIP(value) == nil {
		return ""
	}
	return value
}

// beginOTP creates, sends, and renders a new OTP challenge.
func (s *Server) beginOTP(w http.ResponseWriter, r *http.Request, state OAuthState, id, subject, email string) {
	challenge, err := statedb.GenerateStateToken()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	code, err := otpCode()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	flow := statedb.OTPFlow{FlowID: state.FlowID, ConnectorID: id, Subject: subject, Email: email, ClientID: state.ClientID, RedirectURI: state.RedirectURI, CodeChallenge: state.CodeChallenge, Nonce: state.Nonce, OIDCState: state.OIDCState, Scopes: state.Scopes, RefreshMode: state.RefreshMode, AuthTime: state.AuthTime, OfflineConsent: state.OfflineConsent, Purpose: state.Purpose, DPoPJKT: state.DPoPJKT, PushedAuthorization: state.PushedAuthorization}
	otpTTL := s.config.Email.OTPTTL.Duration()
	expiresAt, err := s.store.CreateOTP(challenge, email, code, flow, s.otpSecret, time.Now(), otpTTL)
	if err != nil {
		http.Error(w, "unable to send code", http.StatusTooManyRequests)
		return
	}
	if err = s.mailer.SendOTP(r.Context(), email, code, expiresAt); err != nil {
		s.logger.Error("send OTP", "error", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.templates.RenderPage(w, "otp", templates.OTPData{Title: "Verify email", ChallengeID: challenge, Message: "A code was sent.", Email: email, ExpiresIn: otpTTL, ExpiresAt: expiresAt})
}

// HandleEmailVerify consumes an OTP and completes authorization.
func (s *Server) HandleEmailVerify(w http.ResponseWriter, r *http.Request) {
	if s.config.Email == nil || s.mailer == nil || len(s.otpSecret) == 0 {
		http.Error(w, "email verification unavailable", http.StatusNotFound)
		return
	}
	if !parseBrowserForm(w, r, "challenge", "code") {
		return
	}
	challengeID := r.PostForm.Get("challenge")
	flow, err := s.store.ConsumeOTP(challengeID, r.PostForm.Get("code"), s.otpSecret, time.Now())
	if err != nil {
		http.Error(w, "invalid code", 400)
		return
	}
	if err = s.store.SaveCredential(flow.ConnectorID, flow.Subject, flow.Email, true, time.Now()); err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	state := OAuthState{
		FlowID:              flow.FlowID,
		ConnectorID:         flow.ConnectorID,
		ClientID:            flow.ClientID,
		RedirectURI:         flow.RedirectURI,
		CodeChallenge:       flow.CodeChallenge,
		Nonce:               flow.Nonce,
		OIDCState:           flow.OIDCState,
		Scopes:              flow.Scopes,
		RefreshMode:         flow.RefreshMode,
		AuthTime:            flow.AuthTime,
		OfflineConsent:      flow.OfflineConsent,
		Purpose:             flow.Purpose,
		DPoPJKT:             flow.DPoPJKT,
		PushedAuthorization: flow.PushedAuthorization,
	}
	s.complete(w, r, state, flow.Subject, flow.Email, true)
}

// HandleEmailResend replaces and sends the code for an active challenge.
func (s *Server) HandleEmailResend(w http.ResponseWriter, r *http.Request) {
	if s.config.Email == nil || s.mailer == nil || len(s.otpSecret) == 0 {
		http.Error(w, "email verification unavailable", http.StatusNotFound)
		return
	}
	if !parseBrowserForm(w, r, "challenge") {
		return
	}
	id := r.PostForm.Get("challenge")
	code, err := otpCode()
	var flow statedb.OTPFlow
	var expiresAt time.Time
	if err == nil {
		otpTTL := s.config.Email.OTPTTL.Duration()
		flow, expiresAt, err = s.store.ResendOTP(id, code, s.otpSecret, time.Now(), otpTTL)
	}
	if err != nil {
		s.logger.Warn("resend OTP", "error", err)
		status := http.StatusInternalServerError
		var retryAfter time.Duration
		var retryAfterSeconds int64
		var resendErr *statedb.OTPResendError
		if errors.As(err, &resendErr) {
			status = http.StatusBadRequest
			retryAfter = resendErr.RetryAfter
			if retryAfter > 0 {
				status = http.StatusTooManyRequests
				retryAfterSeconds = int64((retryAfter + time.Second - 1) / time.Second)
				w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds, 10))
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = s.templates.RenderPage(w, "otp", templates.OTPData{Title: "Verify email", ChallengeID: id, Error: "A new code could not be sent.", Email: flow.Email, ExpiresIn: s.config.Email.OTPTTL.Duration(), RetryAfter: retryAfter, RetryAfterSeconds: retryAfterSeconds})
		return
	}
	if err = s.mailer.SendOTP(r.Context(), flow.Email, code, expiresAt); err != nil {
		s.logger.Warn("resend OTP", "error", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.templates.RenderPage(w, "otp", templates.OTPData{Title: "Verify email", ChallengeID: id, Message: "A new code was sent.", Email: flow.Email, ExpiresIn: s.config.Email.OTPTTL.Duration(), ExpiresAt: expiresAt})
}
