// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package challenge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Verifier validates a challenge response.
type Verifier interface {
	Verify(context.Context, string, string) error
}

// Noop accepts every challenge.
type Noop struct{}

// Verify always accepts the challenge.
func (Noop) Verify(context.Context, string, string) error { return nil }

// Turnstile verifies challenges using Cloudflare Turnstile.
type Turnstile struct {
	Secret string
	Client *http.Client
}

// Verify submits a challenge response to Cloudflare and fails closed.
func (t Turnstile) Verify(ctx context.Context, response, remoteIP string) error {
	if response == "" {
		return fmt.Errorf("challenge required")
	}
	v := url.Values{"secret": {t.Secret}, "response": {response}}
	if remoteIP != "" {
		v.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := t.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("verify challenge: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode challenge response: %w", err)
	}
	if !out.Success {
		if len(out.ErrorCodes) == 0 {
			return fmt.Errorf("challenge rejected")
		}
		return fmt.Errorf("challenge rejected: %s", strings.Join(out.ErrorCodes, ","))
	}
	return nil
}
