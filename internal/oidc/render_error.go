// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"net/http"

	"github.com/truster-dev/truster/v2/internal/templates"
)

// browserFailureReason identifies a browser flow failure without carrying user data.
type browserFailureReason string

const (
	failureAuthorizationCodeCreate              browserFailureReason = "authorization_code_create_failed"
	failureAuthorizationConsentDenied           browserFailureReason = "authorization_consent_denied"
	failureAuthorizationConsentRequired         browserFailureReason = "authorization_consent_required"
	failureAuthorizationCredentialLoad          browserFailureReason = "authorization_credential_load_failed"
	failureAuthorizationCredentialSave          browserFailureReason = "authorization_credential_save_failed"
	failureAuthorizationDPoP                    browserFailureReason = "authorization_dpop_invalid"
	failureAuthorizationDPoPHeaderUnexpected    browserFailureReason = "authorization_dpop_header_unexpected"
	failureAuthorizationDPoPJKT                 browserFailureReason = "authorization_dpop_jkt_invalid"
	failureAuthorizationFlow                    browserFailureReason = "authorization_flow_invalid"
	failureAuthorizationLoginRequired           browserFailureReason = "authorization_login_required"
	failureAuthorizationParameterDuplicate      browserFailureReason = "authorization_parameter_duplicate"
	failureAuthorizationPARRequest              browserFailureReason = "authorization_par_request_invalid"
	failureAuthorizationPKCE                    browserFailureReason = "authorization_pkce_invalid"
	failureAuthorizationPolicyChanged           browserFailureReason = "authorization_policy_changed"
	failureAuthorizationPrompt                  browserFailureReason = "authorization_prompt_invalid"
	failureAuthorizationProfileChanged          browserFailureReason = "authorization_profile_changed"
	failureAuthorizationRedirect                browserFailureReason = "authorization_redirect_invalid"
	failureAuthorizationResponseTypeUnsupported browserFailureReason = "authorization_response_type_unsupported"
	failureAuthorizationScope                   browserFailureReason = "authorization_scope_invalid"
	failureCallbackConnectorMismatch            browserFailureReason = "callback_connector_mismatch"
	failureCallbackConnectorUnavailable         browserFailureReason = "callback_connector_unavailable"
	failureCallbackCredentialEncode             browserFailureReason = "callback_credential_encode_failed"
	failureCallbackCredentialLookup             browserFailureReason = "callback_credential_lookup_failed"
	failureCallbackCredentialSave               browserFailureReason = "callback_credential_save_failed"
	failureCallbackEmail                        browserFailureReason = "callback_email_invalid"
	failureCallbackEmailVerificationUnavailable browserFailureReason = "callback_email_verification_unavailable"
	failureCallbackExchange                     browserFailureReason = "callback_exchange_failed"
	failureCallbackIdentity                     browserFailureReason = "callback_identity_invalid"
	failureCallbackIdentityLookup               browserFailureReason = "callback_identity_lookup_failed"
	failureCallbackStateConsumption             browserFailureReason = "callback_state_consumption_failed"
	failureCallbackState                        browserFailureReason = "callback_state_invalid"
	failureCallbackUpstreamDenied               browserFailureReason = "callback_upstream_denied"
	failureClientPolicyDenied                   browserFailureReason = "client_policy_denied"
	failureClientPolicyUnavailable              browserFailureReason = "client_policy_unavailable"
	failureConnectorStateEncode                 browserFailureReason = "connector_state_encode_failed"
	failureConnectorUnavailable                 browserFailureReason = "connector_unavailable"
	failureConnectorUnknown                     browserFailureReason = "connector_unknown"
	failureConsentMethod                        browserFailureReason = "consent_method_not_allowed"
	failureConsentRender                        browserFailureReason = "consent_render_failed"
	failureConsentStateEncode                   browserFailureReason = "consent_state_encode_failed"
	failureConsentState                         browserFailureReason = "consent_state_invalid"
	failureDuplicateFormField                   browserFailureReason = "duplicate_form_field"
	failureEmailAddress                         browserFailureReason = "email_address_invalid"
	failureEmailConnector                       browserFailureReason = "email_connector_invalid"
	failureEmailConnectorSelection              browserFailureReason = "email_connector_selection_invalid"
	failureEmailResendMethod                    browserFailureReason = "email_resend_method_not_allowed"
	failureEmailSecurityCheck                   browserFailureReason = "email_security_check_failed"
	failureEmailStartMethod                     browserFailureReason = "email_start_method_not_allowed"
	failureEmailState                           browserFailureReason = "email_state_invalid"
	failureEmailVerificationUnavailable         browserFailureReason = "email_verification_unavailable"
	failureEmailVerifyMethod                    browserFailureReason = "email_verify_method_not_allowed"
	failureGrantActionToken                     browserFailureReason = "grant_action_token_failed"
	failureGrantActionsCreate                   browserFailureReason = "grant_actions_create_failed"
	failureGrantListUnavailable                 browserFailureReason = "grant_list_unavailable"
	failureGrantRevoke                          browserFailureReason = "grant_revoke_failed"
	failureGrantRevokeMethod                    browserFailureReason = "grant_revoke_method_not_allowed"
	failureGrantRevokeRender                    browserFailureReason = "grant_revoke_render_failed"
	failureGrantsMethod                         browserFailureReason = "grants_method_not_allowed"
	failureGrantsRender                         browserFailureReason = "grants_render_failed"
	failureIdentitySelectionConnectorMismatch   browserFailureReason = "identity_selection_connector_mismatch"
	failureIdentitySelectionCreate              browserFailureReason = "identity_selection_create_failed"
	failureIdentitySelection                    browserFailureReason = "identity_selection_invalid"
	failureIdentitySelectionRender              browserFailureReason = "identity_selection_render_failed"
	failureIdentitySelectionState               browserFailureReason = "identity_selection_state_invalid"
	failureInvalidAuthorizationRequest          browserFailureReason = "invalid_authorization_request"
	failureInvalidFormBody                      browserFailureReason = "invalid_form_body"
	failureInvalidFormContentType               browserFailureReason = "invalid_form_content_type"
	failureInvalidPushedAuthorizationRequest    browserFailureReason = "invalid_pushed_authorization_request"
	failureInvalidRedirectURI                   browserFailureReason = "invalid_redirect_uri"
	failureOTPChallengeCreate                   browserFailureReason = "otp_challenge_create_failed"
	failureOTPChallenge                         browserFailureReason = "otp_challenge_invalid"
	failureOTPCodeCreate                        browserFailureReason = "otp_code_create_failed"
	failureOTPCodeFormat                        browserFailureReason = "otp_code_format_invalid"
	failureOTPCodeRejected                      browserFailureReason = "otp_code_rejected"
	failureOTPConsume                           browserFailureReason = "otp_consume_failed"
	failureOTPCreate                            browserFailureReason = "otp_create_failed"
	failureOTPCredentialSave                    browserFailureReason = "otp_credential_save_failed"
	failureOTPLookup                            browserFailureReason = "otp_lookup_failed"
	failureOTPRender                            browserFailureReason = "otp_render_failed"
	failureOTPResendDelivery                    browserFailureReason = "otp_resend_delivery_failed"
	failureOTPResend                            browserFailureReason = "otp_resend_failed"
	failureOTPResendRejected                    browserFailureReason = "otp_resend_rejected"
	failureOTPSend                              browserFailureReason = "otp_send_failed"
	failureOTPSendLimit                         browserFailureReason = "otp_send_limit_exceeded"
	failurePushedAuthorization                  browserFailureReason = "pushed_authorization_invalid"
	failurePushedAuthorizationContinuation      browserFailureReason = "pushed_authorization_continuation_invalid"
	failurePushedAuthorizationPolicyUnavailable browserFailureReason = "pushed_authorization_policy_unavailable"
	failurePushedAuthorizationRedirect          browserFailureReason = "pushed_authorization_redirect_invalid"
	failurePushedAuthorizationRequired          browserFailureReason = "pushed_authorization_required"
	failurePushedAuthorizationStateEncode       browserFailureReason = "pushed_authorization_state_encode_failed"
	failurePushedAuthorizationStoreUnavailable  browserFailureReason = "pushed_authorization_store_unavailable"
	failurePushedConsentRender                  browserFailureReason = "pushed_consent_render_failed"
	failureSelectorRender                       browserFailureReason = "selector_render_failed"
	failureSelectorStateAlreadyBound            browserFailureReason = "selector_state_already_bound"
	failureSelectorStateEncode                  browserFailureReason = "selector_state_encode_failed"
	failureSelectorState                        browserFailureReason = "selector_state_invalid"
	failureUnknownClient                        browserFailureReason = "unknown_client"
	failureUnknownPushedAuthorizationClient     browserFailureReason = "unknown_pushed_authorization_client"
	failureUserPolicyDenied                     browserFailureReason = "user_policy_denied"
	failureUserPolicyUnavailable                browserFailureReason = "user_policy_unavailable"
)

// logBrowserFailure records a diagnosable browser failure with non-personal operational attributes.
func (s *Server) logBrowserFailure(status int, reason browserFailureReason, attributes ...any) {
	if s.logger == nil {
		return
	}
	fields := []any{"reason", reason, "status", status}
	fields = append(fields, attributes...)
	if status >= http.StatusInternalServerError {
		s.logger.Error("browser flow failed", fields...)
		return
	}
	s.logger.Info("browser flow rejected", fields...)
}

// renderBrowserError renders consistent user-facing copy for a browser failure.
func (s *Server) renderBrowserError(w http.ResponseWriter, status int, reason browserFailureReason) {
	title := "Unable to continue"
	message := "This request is invalid or has expired. Return to the application and try again."
	switch status {
	case http.StatusForbidden:
		title = "Sign-in not allowed"
		message = "This account is not allowed to sign in. Return to the application or contact an administrator."
	case http.StatusNotFound:
		title = "Sign-in unavailable"
		message = "This sign-in option is unavailable. Return to the application and try again."
	case http.StatusMethodNotAllowed:
		message = "This page cannot be used that way. Return to the application and try again."
	case http.StatusTooManyRequests:
		title = "Please wait"
		message = "Too many attempts were made. Wait a moment, then return to the application and try again."
	default:
		if status >= http.StatusInternalServerError {
			title = "Sign-in temporarily unavailable"
			message = "We couldn't complete sign-in. Return to the application and try again shortly."
		}
	}
	s.renderErrorPage(w, status, reason, title, message)
}

// renderErrorPage renders a browser error with the configured error template.
func (s *Server) renderErrorPage(w http.ResponseWriter, status int, reason browserFailureReason, title, message string) {
	s.logBrowserFailure(status, reason)
	if s.templates == nil {
		http.Error(w, message, status)
		return
	}
	var body bytes.Buffer
	if err := s.templates.RenderPage(&body, "error", templates.ErrorData{Title: title, Message: message}); err != nil {
		if s.logger != nil {
			s.logger.Error("render error page", "reason", reason)
		}
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}
