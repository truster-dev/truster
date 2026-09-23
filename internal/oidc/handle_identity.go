// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"strconv"
	"time"

	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
	"github.com/truster-dev/truster/v2/internal/upstream"
)

// renderIdentitySelection renders all authenticated upstream email candidates.
func (s *Server) renderIdentitySelection(w http.ResponseWriter, stateToken, connectorID string, identity upstream.Identity) {
	token, err := statedb.GenerateStateToken()
	if err == nil {
		err = s.store.CreateIdentitySelection(token, stateToken, connectorID, identity.Subject, identity.Emails, authorizationStateTTL, 5*time.Minute)
	}
	if err != nil {
		s.renderBrowserError(w, http.StatusInternalServerError, failureIdentitySelectionCreate)
		return
	}
	emails := make([]templates.EmailData, len(identity.Emails))
	for i, email := range identity.Emails {
		emails[i] = templates.EmailData{Address: email.Address, Verified: email.Verified, Primary: email.Primary}
	}
	s.renderBrowserPage(w, http.StatusOK, "identity", templates.IdentityData{Title: "Choose an email", Token: token, Emails: emails}, failureIdentitySelectionRender)
}

// HandleIdentitySelect consumes a selection and its original OAuth state exactly once.
func (s *Server) HandleIdentitySelect(w http.ResponseWriter, r *http.Request) {
	if !s.parseBrowserForm(w, r, "token", "index") {
		return
	}
	stateToken, connectorID, subject, emails, err := s.store.ConsumeIdentitySelection(r.PostForm.Get("token"), time.Now())
	index, indexErr := strconv.Atoi(r.PostForm.Get("index"))
	if err != nil || indexErr != nil || index < 0 || index >= len(emails) {
		s.renderBrowserError(w, http.StatusBadRequest, failureIdentitySelection)
		return
	}
	state, err := s.authCodeMgr.DecodeState(stateToken)
	if err != nil {
		s.renderBrowserError(w, http.StatusBadRequest, failureIdentitySelectionState)
		return
	}
	if state.ConnectorID != connectorID {
		s.renderBrowserError(w, http.StatusBadRequest, failureIdentitySelectionConnectorMismatch)
		return
	}
	s.acceptOrChallenge(w, r, *state, connectorID, subject, emails[index])
}
