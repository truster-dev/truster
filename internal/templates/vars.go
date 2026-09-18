// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package templates

import "time"

// ConnectorData describes a sign-in option rendered by the selector.
type ConnectorData struct {
	ID, DisplayName, URL string
	Email                bool
}

// SelectorData supplies data to the sign-in selector template.
type SelectorData struct {
	Title      string
	Screen     string
	State      string
	SiteKey    string
	Connectors []ConnectorData
}

// OTPData supplies data to the OTP entry template.
type OTPData struct {
	Title, ChallengeID, Message, Error, Email string
	ExpiresIn, RetryAfter                     time.Duration
	ExpiresAt                                 time.Time
	RetryAfterSeconds                         int64
}

// ConsentData supplies data to the offline-access consent template.
type ConsentData struct{ Title, State, ClientID string }

// GrantData describes one active grant and its one-use revocation action.
type GrantData struct {
	SID, ClientID, Mode, ActionToken, Email string
	CreatedAt, LastUsedAt, ExpiresAt        time.Time
}

// GrantsData supplies the self-service grant management page.
type GrantsData struct {
	Title, Email, Message string
	Grants                []GrantData
}

// ErrorData supplies data to the error page template.
type ErrorData struct{ Title, Message string }

// EmailData describes one selectable upstream email assertion.
type EmailData struct {
	Address  string
	Verified bool
	Primary  bool
}

// IdentityData supplies data to the identity selection template.
type IdentityData struct {
	Title  string
	Token  string
	Emails []EmailData
}

// OTPEmailData supplies data to OTP email templates.
type OTPEmailData struct {
	Code      string
	ExpiresAt time.Time
	ExpiresIn time.Duration
}
