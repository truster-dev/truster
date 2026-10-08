// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/truster-dev/truster/v3/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubConnector implements OAuth2 authentication with GitHub.
type GitHubConnector struct {
	config   *oauth2.Config
	hostname string
}

// githubEmail contains one email assertion returned by GitHub.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// githubUser contains the stable identifier returned by GitHub.
type githubUser struct {
	ID int64 `json:"id"`
}

// NewGitHubConnector creates a new GitHub OAuth2 connector with the provided configuration.
// It supports both github.com and GitHub Enterprise instances.
func NewGitHubConnector(cfg config.ConnectorConfig, redirectURL, clientID, clientSecret string) *GitHubConnector {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     github.Endpoint,
	}

	hostname := "github.com"
	if cfg.GitHub != nil && cfg.GitHub.Hostname != "" {
		hostname = cfg.GitHub.Hostname
	}
	if hostname != "github.com" {
		oauth2Config.Endpoint = oauth2.Endpoint{AuthURL: "https://" + hostname + "/login/oauth/authorize", TokenURL: "https://" + hostname + "/login/oauth/access_token"}
	}

	return &GitHubConnector{
		config:   oauth2Config,
		hostname: hostname,
	}
}

// AuthCodeURL returns the URL to redirect users to for GitHub OAuth2 authentication.
func (c *GitHubConnector) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.config.AuthCodeURL(state, opts...)
}

// Exchange exchanges an authorization code for an access token from GitHub.
func (c *GitHubConnector) Exchange(ctx context.Context, code string) (*Credential, error) {
	token, err := c.config.Exchange(ctx, code)
	if err != nil {
		return nil, ClassifyError("code exchange", err)
	}
	return NormalizeCredential(token, time.Now(), token.RefreshToken == ""), nil
}

// Refresh renews a GitHub OAuth credential when GitHub supplied a refresh token.
func (c *GitHubConnector) Refresh(ctx context.Context, credential *Credential) (*Credential, error) {
	if credential.RefreshToken == "" {
		return credential, nil
	}
	forced := *credential.OAuthToken()
	forced.AccessToken = ""
	forced.Expiry = time.Time{}
	refreshed, err := c.config.TokenSource(ctx, &forced).Token()
	if err != nil {
		return nil, ClassifyError("credential refresh", err)
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = credential.RefreshToken
	}
	return NormalizeCredential(refreshed, time.Now(), false), nil
}

// GetIdentity retrieves the stable user ID and every email assertion from GitHub.
func (c *GitHubConnector) GetIdentity(ctx context.Context, token *oauth2.Token) (Identity, error) {
	client := c.config.Client(ctx, token)

	apiBase := fmt.Sprintf("https://api.%s", c.hostname)
	if c.hostname != "github.com" {
		apiBase = fmt.Sprintf("https://%s/api/v3", c.hostname)
	}
	userResp, err := client.Get(apiBase + "/user")
	if err != nil {
		return Identity{}, ClassifyError("user", err)
	}
	defer func() { _ = userResp.Body.Close() }()
	if userResp.StatusCode != http.StatusOK {
		return Identity{}, classifyGitHubStatus("user", userResp)
	}
	var user githubUser
	if err := json.NewDecoder(userResp.Body).Decode(&user); err != nil || user.ID == 0 {
		return Identity{}, fmt.Errorf("invalid GitHub user")
	}

	resp, err := client.Get(apiBase + "/user/emails")
	if err != nil {
		return Identity{}, ClassifyError("emails", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return Identity{}, classifyGitHubStatus("emails", resp)
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return Identity{}, fmt.Errorf("failed to decode emails: %w", err)
	}

	identity := Identity{Subject: fmt.Sprint(user.ID)}
	noreplyDomain := "@users.noreply." + strings.ToLower(c.hostname)
	for _, email := range emails {
		if email.Email != "" && !strings.HasSuffix(strings.ToLower(email.Email), noreplyDomain) {
			identity.Emails = append(identity.Emails, Email{Address: email.Email, Verified: email.Verified, Primary: email.Primary})
		}
	}
	if len(identity.Emails) == 0 {
		return Identity{}, fmt.Errorf("no email found")
	}
	return identity, nil
}

// classifyGitHubStatus recognizes GitHub's 403 secondary and primary rate limits.
func classifyGitHubStatus(operation string, response *http.Response) error {
	retry := response.Header.Get("Retry-After")
	if response.StatusCode == http.StatusForbidden && (retry != "" || response.Header.Get("X-RateLimit-Remaining") == "0" || response.Header.Get("X-RateLimit-Reset") != "") {
		return &ConnectorError{Kind: ErrorRateLimit, RetryAfter: retry, Operation: operation}
	}
	return ClassifyHTTPStatus(operation, response.StatusCode, retry)
}
