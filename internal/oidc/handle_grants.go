// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"net/http"
	"time"

	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
)

// HandleGrants starts a dedicated authentication flow that cannot issue tokens.
func (s *Server) HandleGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.renderBrowserError(w, r, http.StatusMethodNotAllowed, failureGrantsMethod)
		return
	}
	s.continueAuthorization(w, r, OAuthState{Purpose: "manage_grants", AuthTime: time.Now().UTC()})
}

// renderGrants renders active grants with fresh one-use action tokens.
func (s *Server) renderGrants(w http.ResponseWriter, r *http.Request, email string) {
	now := time.Now().UTC()
	grants, err := s.store.ListActiveGrants(email, now)
	if err != nil {
		s.renderErrorPage(w, r, http.StatusServiceUnavailable, failureGrantListUnavailable, "Grant management unavailable", "We couldn't load your active grants. Return and try again shortly.")
		return
	}
	data := templates.GrantsData{PageData: s.pageData(r), Title: "Active grants", Email: email}
	actions := make([]statedb.GrantAction, 0, len(grants))
	for _, grant := range grants {
		token, e := statedb.GenerateStateToken()
		if e != nil {
			s.renderErrorPage(w, r, http.StatusInternalServerError, failureGrantActionToken, "Grant management unavailable", "We couldn't load your active grants. Return and try again shortly.")
			return
		}
		actions = append(actions, statedb.GrantAction{Token: token, SID: grant.SID})
		data.Grants = append(data.Grants, templates.GrantData{SID: grant.SID, ClientID: grant.ClientID, Mode: grant.Mode, ActionToken: token, Email: email, CreatedAt: grant.CreatedAt, LastUsedAt: grant.LastUsedAt, ExpiresAt: grant.ExpiresAt})
	}
	if err = s.store.CreateGrantActions(actions, email, "revoke", now, now.Add(5*time.Minute)); err != nil {
		s.renderErrorPage(w, r, http.StatusServiceUnavailable, failureGrantActionsCreate, "Grant management unavailable", "We couldn't load your active grants. Return and try again shortly.")
		return
	}
	s.renderBrowserPage(w, r, http.StatusOK, "grants", data, failureGrantsRender)
}

// HandleGrantRevoke atomically consumes a CSRF action and revokes its bound grant.
func (s *Server) HandleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.renderBrowserError(w, r, http.StatusMethodNotAllowed, failureGrantRevokeMethod)
		return
	}
	if !s.parseBrowserForm(w, r, "email", "action_token", "sid") {
		return
	}
	email, err := normalizeEmail(r.PostForm.Get("email"))
	if err != nil {
		err = statedb.ErrInvalidGrant
	} else {
		err = s.store.ConsumeGrantActionAndRevoke(r.PostForm.Get("action_token"), email, r.PostForm.Get("sid"), "revoke", time.Now().UTC())
	}
	status, message := http.StatusOK, "The grant was revoked. Existing access tokens may remain valid until they expire."
	if err != nil {
		status = http.StatusBadRequest
		message = "This revocation action is invalid, expired, or already used."
		if !errors.Is(err, statedb.ErrInvalidGrant) {
			status = http.StatusServiceUnavailable
			message = "Grant management is temporarily unavailable."
		}
	}
	if err != nil {
		s.logBrowserFailure(status, failureGrantRevoke)
	}
	s.renderBrowserPage(w, r, status, "grants", templates.GrantsData{PageData: s.pageData(r), Title: "Grant revocation", Message: message}, failureGrantRevokeRender)
}
