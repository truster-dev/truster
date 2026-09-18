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
		s.renderBrowserError(w, http.StatusMethodNotAllowed, failureEmailStartMethod)
		return
	}
	if !s.parseBrowserForm(w, r, "state", "connector", "cf-turnstile-response", "email") {
		return
	}
	state, err := s.authCodeMgr.DecodeState(r.PostForm.Get("state"))
	if err != nil || state.ConnectorID != "" {
		s.renderBrowserError(w, http.StatusBadRequest, failureEmailState)
		return
	}
	connectorID := r.PostForm.Get("connector")
	connector, ok := s.config.UserLoginConnectors[connectorID]
	if !ok || connector.Type != "email" {
		s.renderBrowserError(w, http.StatusBadRequest, failureEmailConnector)
		return
	}
	state.ConnectorID = connectorID
	remoteIP := ""
	if s.config.Email != nil && s.config.Email.Turnstile != nil && s.config.Email.Turnstile.RemoteIP != nil {
		remoteIP = remoteIPFromRequest(r, s.config.Email.Turnstile.RemoteIP.Source, s.config.Email.Turnstile.RemoteIP.Header)
	}
	if err = s.challenge.Verify(r.Context(), r.PostForm.Get("cf-turnstile-response"), remoteIP); err != nil {
		s.renderErrorPage(w, http.StatusBadRequest, failureEmailSecurityCheck, "Security check failed", "We couldn't verify the security check. Return to sign in and try again.")
		return
	}
	email, err := normalizeEmail(r.PostForm.Get("email"))
	if err != nil {
		s.renderErrorPage(w, http.StatusBadRequest, failureEmailAddress, "Check your email address", "Enter a valid email address and try again.")
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
		s.renderBrowserError(w, http.StatusInternalServerError, failureOTPChallengeCreate)
		return
	}
	code, err := otpCode()
	if err != nil {
		s.renderBrowserError(w, http.StatusInternalServerError, failureOTPCodeCreate)
		return
	}
	flow := statedb.OTPFlow{FlowID: state.FlowID, ConnectorID: id, Subject: subject, Email: email, ClientID: state.ClientID, RedirectURI: state.RedirectURI, CodeChallenge: state.CodeChallenge, Nonce: state.Nonce, OIDCState: state.OIDCState, Scopes: state.Scopes, RefreshMode: state.RefreshMode, AuthTime: state.AuthTime, OfflineConsent: state.OfflineConsent, Purpose: state.Purpose, DPoPJKT: state.DPoPJKT, PushedAuthorization: state.PushedAuthorization}
	otpTTL := s.config.Email.OTPTTL.Duration()
	expiresAt, err := s.store.CreateOTP(challenge, email, code, flow, s.otpSecret, time.Now(), otpTTL)
	if err != nil {
		if errors.Is(err, statedb.ErrOTPSendLimit) {
			s.renderErrorPage(w, http.StatusTooManyRequests, failureOTPSendLimit, "Please wait", "Too many verification codes were requested. Wait before starting sign-in again.")
		} else {
			s.renderErrorPage(w, http.StatusInternalServerError, failureOTPCreate, "Verification code unavailable", "We couldn't send a verification code. Wait a moment, then start sign-in again.")
		}
		return
	}
	if err = s.mailer.SendOTP(r.Context(), email, code, expiresAt); err != nil {
		// Delivery outcomes stay indistinguishable to prevent address enumeration.
		s.logBrowserFailure(http.StatusBadGateway, failureOTPSend)
	}
	s.renderBrowserPage(w, http.StatusOK, "otp", templates.OTPData{Title: "Verify email", ChallengeID: challenge, Message: "A code was sent.", Email: email, ExpiresIn: otpTTL, ExpiresAt: expiresAt}, failureOTPRender)
}

// HandleEmailVerify consumes an OTP and completes authorization.
func (s *Server) HandleEmailVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.renderBrowserError(w, http.StatusMethodNotAllowed, failureEmailVerifyMethod)
		return
	}
	if s.config.Email == nil || s.mailer == nil || len(s.otpSecret) == 0 {
		s.renderErrorPage(w, http.StatusNotFound, failureEmailVerificationUnavailable, "Email verification unavailable", "Email verification isn't available. Return and choose another sign-in method.")
		return
	}
	if !s.parseBrowserForm(w, r, "challenge", "code") {
		return
	}
	challengeID := r.PostForm.Get("challenge")
	code := r.PostForm.Get("code")
	if len(code) != 8 {
		s.renderErrorPage(w, http.StatusBadRequest, failureOTPCodeFormat, "Check your verification code", "Enter the 8-digit code from your email and try again.")
		return
	}
	now := time.Now()
	activeFlow, expiresAt, lookupErr := s.store.OTPFlow(challengeID, now)
	if lookupErr != nil {
		if errors.Is(lookupErr, statedb.ErrInvalidOTPChallenge) {
			s.renderErrorPage(w, http.StatusBadRequest, failureOTPChallenge, "Verification request unavailable", "This verification request has expired or can no longer be used. Start sign-in again.")
		} else {
			s.renderErrorPage(w, http.StatusInternalServerError, failureOTPLookup, "Email verification unavailable", "We couldn't verify your code right now. Wait a moment and try again.")
		}
		return
	}
	flow, err := s.store.ConsumeOTP(challengeID, code, s.otpSecret, now)
	if err != nil {
		if errors.Is(err, statedb.ErrInvalidOTPCode) {
			s.logBrowserFailure(http.StatusBadRequest, failureOTPCodeRejected)
			s.renderBrowserPage(w, http.StatusBadRequest, "otp", templates.OTPData{Title: "Verify email", ChallengeID: challengeID, Email: activeFlow.Email, Error: "That code isn't valid. Check it and try again.", ExpiresAt: expiresAt, ExpiresIn: expiresAt.Sub(now)}, failureOTPRender)
			return
		}
		if errors.Is(err, statedb.ErrInvalidOTPChallenge) {
			s.renderErrorPage(w, http.StatusBadRequest, failureOTPChallenge, "Verification request unavailable", "This verification request has expired or can no longer be used. Start sign-in again.")
		} else {
			s.renderErrorPage(w, http.StatusInternalServerError, failureOTPConsume, "Email verification unavailable", "We couldn't verify your code right now. Wait a moment and try again.")
		}
		return
	}
	if err = s.store.SaveCredential(flow.ConnectorID, flow.Subject, flow.Email, true, time.Now()); err != nil {
		s.redirectAuthorizationError(w, r, flow.RedirectURI, flow.OIDCState, oauthAuthorizationErrorServer, failureOTPCredentialSave)
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
	if r.Method != http.MethodPost {
		s.renderBrowserError(w, http.StatusMethodNotAllowed, failureEmailResendMethod)
		return
	}
	if s.config.Email == nil || s.mailer == nil || len(s.otpSecret) == 0 {
		s.renderErrorPage(w, http.StatusNotFound, failureEmailVerificationUnavailable, "Email verification unavailable", "Email verification isn't available. Return and choose another sign-in method.")
		return
	}
	if !s.parseBrowserForm(w, r, "challenge") {
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
		status := http.StatusInternalServerError
		reason := failureOTPResend
		var retryAfter time.Duration
		var retryAfterSeconds int64
		var resendErr *statedb.OTPResendError
		if errors.As(err, &resendErr) {
			status = http.StatusBadRequest
			reason = failureOTPResendRejected
			retryAfter = resendErr.RetryAfter
			if retryAfter > 0 {
				status = http.StatusTooManyRequests
				retryAfterSeconds = int64((retryAfter + time.Second - 1) / time.Second)
				w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds, 10))
			}
		}
		s.logBrowserFailure(status, reason)
		s.renderBrowserPage(w, status, "otp", templates.OTPData{Title: "Verify email", ChallengeID: id, Error: "A new code could not be sent. Wait a moment and try again.", Email: flow.Email, ExpiresIn: s.config.Email.OTPTTL.Duration(), RetryAfter: retryAfter, RetryAfterSeconds: retryAfterSeconds}, failureOTPRender)
		return
	}
	if err = s.mailer.SendOTP(r.Context(), flow.Email, code, expiresAt); err != nil {
		// Delivery outcomes stay indistinguishable to prevent address enumeration.
		s.logBrowserFailure(http.StatusBadGateway, failureOTPResendDelivery)
	}
	s.renderBrowserPage(w, http.StatusOK, "otp", templates.OTPData{Title: "Verify email", ChallengeID: id, Message: "A new code was sent.", Email: flow.Email, ExpiresIn: s.config.Email.OTPTTL.Duration(), ExpiresAt: expiresAt}, failureOTPRender)
}
