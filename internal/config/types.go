// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration is a positive configuration duration.
// Its JSON representation uses the Go standard library duration syntax.
type Duration time.Duration

// UnmarshalJSON parses a canonical human duration and records its presence.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := ParseDuration(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// MarshalJSON emits a canonical duration string, or null for an absent duration.
func (d Duration) MarshalJSON() ([]byte, error) {
	if d == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(d.Duration().String())
}

// Duration returns the standard-library duration value.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// ParseDuration parses a positive Go duration string.
func ParseDuration(value string) (time.Duration, error) {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", value, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return parsed, nil
}

// Config represents the top-level configuration structure for truster.
type Config struct {
	Schema              string                       `json:"$schema,omitempty"`
	IssuerURL           string                       `json:"issuer_url"`
	HTTPListenAddr      string                       `json:"http_listen_addr"`
	ServingCertificate  *ServingCertificateConfig    `json:"serving_certificate,omitempty"`
	SigningAlgorithm    string                       `json:"signing_algorithm,omitempty"`
	JWKSKID             string                       `json:"jwks_kid,omitempty"`
	AccessTokenTTL      Duration                     `json:"access_token_ttl,omitempty"`
	IDTokenTTL          Duration                     `json:"id_token_ttl,omitempty"`
	Secrets             SecretsConfig                `json:"secrets"`
	UserLoginConnectors map[string]ConnectorConfig   `json:"user_login_connectors"`
	ServiceTokenIssuers map[string]TrustIssuerConfig `json:"service_token_issuers,omitempty"`
	TemplatesDir        string                       `json:"templates_dir,omitempty"`
	Email               *EmailConfig                 `json:"email,omitempty"`
	StaticPolicy        StaticPolicyConfig           `json:"static_policy,omitzero"`
	StateDatabase       *StateDatabaseConfig         `json:"state_database,omitempty"`
	PolicyDatabase      *PolicyDatabaseConfig        `json:"policy_database,omitempty"`
}

// ServingCertificateConfig configures the certificate used by the HTTPS server.
type ServingCertificateConfig struct {
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
}

// StaticPolicyConfig contains authorization policy defined in the configuration file.
type StaticPolicyConfig struct {
	RequireUserGroupsFromPolicy *bool                          `json:"require_user_groups_from_policy,omitempty"`
	DefaultRedirectURIs         []string                       `json:"default_redirect_uris,omitempty"`
	UserGroupMappings           map[string]map[string][]string `json:"user_group_mappings,omitempty"`
	TrustPolicies               map[string]TrustPolicyConfig   `json:"trust_policies,omitempty"`
	Clients                     map[string]ClientConfig        `json:"clients,omitempty"`
}

// StateDatabaseConfig configures the authoritative protocol-state database.
type StateDatabaseConfig struct {
	Driver                 string                         `json:"driver,omitempty"`
	Path                   string                         `json:"path,omitempty"`
	ConnectionStringSecret string                         `json:"connection_string_secret,omitempty"`
	MaxConnections         int                            `json:"max_connections,omitempty"`
	QueryTimeout           Duration                       `json:"query_timeout,omitempty"`
	Migrations             *StateDatabaseMigrationsConfig `json:"migrations,omitempty"`
}

// StateDatabaseMigrationsConfig configures the optional migration-only database credential.
type StateDatabaseMigrationsConfig struct {
	ConnectionStringSecret string `json:"connection_string_secret,omitempty"`
}

// PolicyDatabaseConfig configures a supplemental policy database.
type PolicyDatabaseConfig struct {
	Driver                 string                  `json:"driver"`
	ConnectionStringSecret string                  `json:"connection_string_secret"`
	RedirectURIs           []string                `json:"redirect_uris"`
	ClientDefaults         PolicyClientDefaults    `json:"client_defaults,omitempty"`
	Queries                PolicyQueries           `json:"queries,omitempty"`
	ClientLookupCache      ClientLookupCacheConfig `json:"client_lookup_cache,omitempty"`
	PolicyBuildCache       PolicyBuildCacheConfig  `json:"policy_build_cache,omitempty"`
	QueryTimeout           Duration                `json:"query_timeout,omitempty"`
	MaxConnections         int32                   `json:"max_connections,omitempty"`
	MaxTrustRows           int                     `json:"max_trust_rows,omitempty"`
	MaxGroups              int                     `json:"max_groups,omitempty"`
	MaxGroupBytes          int                     `json:"max_group_bytes,omitempty"`
	MaxJSONBytes           int                     `json:"max_json_bytes,omitempty"`
}

// PolicyClientDefaults defines settings shared by dynamically resolved clients.
type PolicyClientDefaults struct {
	RequireUserGroupsFromPolicy *bool              `json:"require_user_groups_from_policy,omitempty"`
	RefreshTokens               RefreshTokenConfig `json:"refresh_tokens,omitempty"`
	DPoP                        DPoPConfig         `json:"dpop,omitempty"`
	RequirePAR                  bool               `json:"require_par,omitempty"`
}

// PolicyQueries contains the three parameterized policy database queries.
type PolicyQueries struct {
	ClientExists  string `json:"client_exists"`
	UserAccess    string `json:"user_access"`
	TrustBindings string `json:"trust_bindings"`
}

// ClientLookupCacheConfig bounds positive and negative client existence lookups.
type ClientLookupCacheConfig struct {
	TTL         Duration `json:"ttl,omitempty"`
	NegativeTTL Duration `json:"negative_ttl,omitempty"`
	MaxEntries  int      `json:"max_entries,omitempty"`
}

// PolicyBuildCacheConfig bounds immutable built trust policy artifacts.
type PolicyBuildCacheConfig struct {
	MaxEntries int `json:"max_entries,omitempty"`
}

// SecretsConfig defines the secrets provider configuration.
// Supports AWS Secrets Manager, AWS Systems Manager Parameter Store,
// Google Secret Manager, Azure Key Vault, file, and env-based secrets.
type SecretsConfig struct {
	Provider          string `json:"provider"`
	SigningKeyName    string `json:"signing_key_name"`
	EncryptionKeyName string `json:"encryption_key_name,omitempty"`
	AWSRegion         string `json:"aws_region,omitempty"`
	AzureKeyVaultURL  string `json:"azure_keyvault_url"`
	FileDirectory     string `json:"file_directory,omitempty"`
}

// ConnectorConfig defines the upstream OAuth provider configuration.
// Supports Google, GitHub, and generic OAuth2/OIDC providers.
type ConnectorConfig struct {
	Type              string         `json:"type"`
	DisplayName       string         `json:"display_name"`
	Order             int            `json:"order,omitempty"`
	CredentialsSecret string         `json:"credentials_secret,omitempty"`
	Scopes            []string       `json:"scopes"`
	Google            *GoogleConfig  `json:"google,omitempty"`
	GitHub            *GitHubConfig  `json:"github,omitempty"`
	Generic           *GenericConfig `json:"generic,omitempty"`
}

// GoogleConfig contains Google-specific OAuth configuration options.
type GoogleConfig struct {
	HostedDomain string `json:"hd"`
}

// GitHubConfig contains GitHub-specific OAuth configuration options.
type GitHubConfig struct {
	Hostname string `json:"hostname"`
}

// GenericConfig contains generic OAuth2/OIDC provider configuration options.
type GenericConfig struct {
	AuthorizationURL   string                `json:"authorization_url"`
	TokenURL           string                `json:"token_url"`
	UserinfoURL        string                `json:"userinfo_url"`
	EmailField         string                `json:"email_field,omitempty"`          // JSON field name for email in userinfo response
	EmailVerifiedField string                `json:"email_verified_field,omitempty"` // JSON field name for email verification status
	SubjectField       string                `json:"subject_field,omitempty"`
	Refresh            *GenericRefreshConfig `json:"refresh,omitempty"`
}

// GenericRefreshConfig configures renewable upstream credential acquisition.
type GenericRefreshConfig struct {
	Scopes              []string          `json:"scopes,omitempty"`
	AuthorizationParams map[string]string `json:"authorization_params,omitempty"`
}

// EmailConfig controls optional email verification and direct email authentication.
type EmailConfig struct {
	VerificationMode string           `json:"verification_mode"`
	OTPSecretName    string           `json:"otp_secret_name"`
	OTPTTL           Duration         `json:"otp_ttl,omitempty"`
	SMTP             *SMTPConfig      `json:"smtp,omitempty"`
	Turnstile        *TurnstileConfig `json:"turnstile,omitempty"`
}

// SMTPConfig configures the verification email SMTP transport.
type SMTPConfig struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	FromName          string `json:"from_name"`
	FromAddress       string `json:"from_address"`
	CredentialsSecret string `json:"credentials_secret"`
	TLSMode           string `json:"tls_mode,omitempty"`
}

// TurnstileConfig configures Cloudflare Turnstile verification.
type TurnstileConfig struct {
	SiteKey    string                   `json:"site_key"`
	SecretName string                   `json:"secret_name"`
	RemoteIP   *TurnstileRemoteIPConfig `json:"remote_ip,omitempty"`
}

// TurnstileRemoteIPConfig selects the trusted source of the visitor IP sent to Turnstile.
type TurnstileRemoteIPConfig struct {
	Source string `json:"source"`
	Header string `json:"header,omitempty"`
}

// ClientConfig defines OIDC client-specific configuration.
// Each client can have custom redirect URIs and a user group mapping.
type ClientConfig struct {
	RedirectURIs                []string             `json:"redirect_uris,omitempty"`
	UserGroupMapping            string               `json:"user_group_mapping,omitempty"`
	RequireUserGroupsFromPolicy *bool                `json:"require_user_groups_from_policy,omitempty"`
	RefreshTokens               RefreshTokenConfig   `json:"refresh_tokens,omitempty"`
	TrustBindings               []TrustBindingConfig `json:"trust_bindings,omitempty"`
	DPoP                        DPoPConfig           `json:"dpop,omitempty"`
	RequirePAR                  bool                 `json:"require_par,omitempty"`
}

// DPoPConfig controls sender-constrained proof requirements for a client.
type DPoPConfig struct {
	Mode             string `json:"mode,omitempty"`
	SigningAlgorithm string `json:"signing_algorithm,omitempty"`
}

// RefreshTokenConfig controls refresh issuance and snapshotted grant lifetimes.
type RefreshTokenConfig struct {
	Enabled            bool     `json:"enabled,omitempty"`
	AllowOfflineAccess bool     `json:"allow_offline_access,omitempty"`
	SessionIdleTTL     Duration `json:"session_idle_ttl,omitempty"`
	SessionAbsoluteTTL Duration `json:"session_absolute_ttl,omitempty"`
	OfflineIdleTTL     Duration `json:"offline_idle_ttl,omitempty"`
	OfflineAbsoluteTTL Duration `json:"offline_absolute_ttl,omitempty"`
}

// ShouldRequireUserGroupsFromPolicy returns whether policy must resolve user groups.
// It checks the client-specific setting first, falling back to the policy default.
// If neither is set, it defaults to true.
func (c *ClientConfig) ShouldRequireUserGroupsFromPolicy(policyDefault *bool) bool {
	if c.RequireUserGroupsFromPolicy != nil {
		return *c.RequireUserGroupsFromPolicy
	}
	if policyDefault != nil {
		return *policyDefault
	}
	return true
}
