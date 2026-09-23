// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

const (
	defaultClientExistsQuery  = `SELECT EXISTS (SELECT 1 FROM truster_policy.clients WHERE client_id = $1) AS exists`
	defaultUserAccessQuery    = `SELECT users.subject IS NOT NULL AS allowed, COALESCE(users.groups, ARRAY[]::text[]) AS groups FROM (VALUES ($1::text, $2::text)) AS input(client_id, subject) LEFT JOIN truster_policy.users USING (client_id, subject)`
	defaultTrustBindingsQuery = `SELECT client_id, issuer_id, binding_id, subject, required_claims, policy_claims, binding_claims, groups FROM truster_policy.trust_bindings WHERE client_id = $1 AND issuer_id = $2 ORDER BY binding_id`
)

const DefaultSigningAlgorithm = "RS256"

var supportedSigningAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"EdDSA": {},
}

// Load reads and parses a JSONC configuration file from the given path.
// It validates the configuration and returns an error if validation fails.
// The path parameter must be non-empty.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return Parse(data)
}

// Parse parses and validates JSONC configuration data.
func Parse(data []byte) (*Config, error) {
	data, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := validatePolicyFields(data); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	if err := validateStateDatabaseFields(data, cfg.StateDatabase); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	applyDurationDefault(&cfg.AccessTokenTTL, 15*time.Minute)
	applyDurationDefault(&cfg.IDTokenTTL, 15*time.Minute)
	if cfg.SigningAlgorithm == "" {
		cfg.SigningAlgorithm = DefaultSigningAlgorithm
	}

	if override := os.Getenv("TRUSTER_TEMPLATES_DIR"); override != "" {
		cfg.TemplatesDir = override
	}
	if cfg.Email != nil && cfg.Email.VerificationMode == "" {
		cfg.Email.VerificationMode = "disabled"
	}
	if cfg.Email != nil {
		applyDurationDefault(&cfg.Email.OTPTTL, 5*time.Minute)
	}
	for id, connector := range cfg.UserLoginConnectors {
		if connector.Generic != nil && connector.Generic.SubjectField == "" {
			connector.Generic.SubjectField = "sub"
			cfg.UserLoginConnectors[id] = connector
		}
	}
	for id, client := range cfg.StaticPolicy.Clients {
		applyRefreshDefaults(&client.RefreshTokens)
		applyDPoPDefaults(&client.DPoP)
		cfg.StaticPolicy.Clients[id] = client
	}
	if policyDatabase := cfg.PolicyDatabase; policyDatabase != nil {
		if strings.TrimSpace(policyDatabase.Queries.ClientExists) == "" {
			policyDatabase.Queries.ClientExists = defaultClientExistsQuery
		}
		if strings.TrimSpace(policyDatabase.Queries.UserAccess) == "" {
			policyDatabase.Queries.UserAccess = defaultUserAccessQuery
		}
		if strings.TrimSpace(policyDatabase.Queries.TrustBindings) == "" {
			policyDatabase.Queries.TrustBindings = defaultTrustBindingsQuery
		}
		applyRefreshDefaults(&policyDatabase.ClientDefaults.RefreshTokens)
		applyDPoPDefaults(&policyDatabase.ClientDefaults.DPoP)
		applyDurationDefault(&policyDatabase.ClientLookupCache.TTL, 5*time.Minute)
		applyDurationDefault(&policyDatabase.ClientLookupCache.NegativeTTL, 30*time.Second)
		applyDurationDefault(&policyDatabase.QueryTimeout, 500*time.Millisecond)
		if policyDatabase.ClientLookupCache.MaxEntries == 0 {
			policyDatabase.ClientLookupCache.MaxEntries = 10000
		}
		if policyDatabase.PolicyBuildCache.MaxEntries == 0 {
			policyDatabase.PolicyBuildCache.MaxEntries = 10000
		}
		if policyDatabase.MaxConnections == 0 {
			policyDatabase.MaxConnections = 4
		}
		if policyDatabase.MaxTrustRows == 0 {
			policyDatabase.MaxTrustRows = 100
		}
		if policyDatabase.MaxGroups == 0 {
			policyDatabase.MaxGroups = 100
		}
		if policyDatabase.MaxGroupBytes == 0 {
			policyDatabase.MaxGroupBytes = 256
		}
		if policyDatabase.MaxJSONBytes == 0 {
			policyDatabase.MaxJSONBytes = 64 << 10
		}
	}
	if cfg.StateDatabase == nil {
		cfg.StateDatabase = &StateDatabaseConfig{}
	}
	stateDatabase := cfg.StateDatabase
	if stateDatabase.Driver == "" {
		stateDatabase.Driver = "sqlite"
	}
	if stateDatabase.Driver == "sqlite" && stateDatabase.Path == "" {
		stateDatabase.Path = "data/truster-state.db"
	}
	if stateDatabase.Driver == "postgresql" {
		applyDurationDefault(&stateDatabase.QueryTimeout, 5*time.Second)
		if stateDatabase.MaxConnections == 0 {
			stateDatabase.MaxConnections = 16
		}
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// validatePolicyFields rejects explicit nulls that the configuration schema does not permit.
func validatePolicyFields(data []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode policy fields: %w", err)
	}
	if err := validateCanonicalPolicyFields(document, "configuration", "service_token_issuers", "static_policy", "policy_database"); err != nil {
		return err
	}
	if raw, present := document["service_token_issuers"]; present {
		if err := validateServiceTokenIssuerFields(raw); err != nil {
			return err
		}
	}

	if raw, present := document["static_policy"]; present {
		if err := validateStaticPolicyFields(raw); err != nil {
			return err
		}
	}
	if raw, present := document["policy_database"]; present {
		if err := validatePolicyDatabaseFields(raw); err != nil {
			return err
		}
	}
	return nil
}

// validateServiceTokenIssuerFields validates presence-sensitive issuer fields.
func validateServiceTokenIssuerFields(raw json.RawMessage) error {
	issuers, err := decodePolicyObject(raw, "service_token_issuers")
	if err != nil {
		return err
	}
	for name, issuerRaw := range issuers {
		path := "service_token_issuers." + name
		issuer, err := decodePolicyObject(issuerRaw, path)
		if err != nil {
			return err
		}
		if err := validateCanonicalPolicyFields(issuer, path, "provider", "issuer_url", "signing_algs", "max_token_age"); err != nil {
			return err
		}
		if err := rejectNullPolicyFields(issuer, path, "provider", "issuer_url", "signing_algs", "max_token_age"); err != nil {
			return err
		}
	}
	return nil
}

// validateStaticPolicyFields validates presence-sensitive static policy fields.
func validateStaticPolicyFields(raw json.RawMessage) error {
	fields, err := decodePolicyObject(raw, "static_policy")
	if err != nil {
		return err
	}
	if err := validateCanonicalPolicyFields(fields, "static_policy", "require_user_groups_from_policy", "default_redirect_uris", "user_group_mappings", "trust_policies", "clients"); err != nil {
		return err
	}
	for _, name := range []string{"require_user_groups_from_policy", "default_redirect_uris", "user_group_mappings", "trust_policies", "clients"} {
		if err := rejectNullPolicyFields(fields, "static_policy", name); err != nil {
			return err
		}
	}
	if raw, present := fields["user_group_mappings"]; present {
		if err := validateUserGroupMappingFields(raw); err != nil {
			return err
		}
	}
	if raw, present := fields["trust_policies"]; present {
		if err := validateTrustPolicyFields(raw); err != nil {
			return err
		}
	}

	clientsRaw, present := fields["clients"]
	if !present {
		return nil
	}
	clients, err := decodePolicyObject(clientsRaw, "static_policy.clients")
	if err != nil {
		return err
	}
	for id, clientRaw := range clients {
		path := "static_policy.clients." + id
		client, err := decodePolicyObject(clientRaw, path)
		if err != nil {
			return err
		}
		if err := validateCanonicalPolicyFields(client, path, "redirect_uris", "user_group_mapping", "require_user_groups_from_policy", "refresh_tokens", "trust_bindings", "dpop", "require_par"); err != nil {
			return err
		}
		if err := rejectNullPolicyFields(client, path, "redirect_uris", "user_group_mapping", "require_user_groups_from_policy", "refresh_tokens", "trust_bindings", "dpop", "require_par"); err != nil {
			return err
		}
		if dpopRaw, ok := client["dpop"]; ok {
			if err := validateDPoPFields(dpopRaw, path+".dpop"); err != nil {
				return err
			}
		}
		if refreshRaw, ok := client["refresh_tokens"]; ok {
			refresh, err := decodePolicyObject(refreshRaw, path+".refresh_tokens")
			if err != nil {
				return err
			}
			if err := validateCanonicalPolicyFields(refresh, path+".refresh_tokens", "enabled", "allow_offline_access", "session_idle_ttl", "session_absolute_ttl", "offline_idle_ttl", "offline_absolute_ttl"); err != nil {
				return err
			}
			if err := rejectNullPolicyFields(refresh, path+".refresh_tokens", "enabled", "allow_offline_access", "session_idle_ttl", "session_absolute_ttl", "offline_idle_ttl", "offline_absolute_ttl"); err != nil {
				return err
			}
		}
		if bindingsRaw, ok := client["trust_bindings"]; ok {
			if err := validateTrustBindingFields(bindingsRaw, path+".trust_bindings"); err != nil {
				return err
			}
		}
	}
	return nil
}

// validatePolicyDatabaseFields validates presence-sensitive policy database defaults.
func validatePolicyDatabaseFields(raw json.RawMessage) error {
	database, err := decodePolicyObject(raw, "policy_database")
	if err != nil {
		return err
	}
	if err := validateCanonicalPolicyFields(database, "policy_database", "client_defaults"); err != nil {
		return err
	}
	defaultsRaw, present := database["client_defaults"]
	if !present {
		return nil
	}
	defaults, err := decodePolicyObject(defaultsRaw, "policy_database.client_defaults")
	if err != nil {
		return err
	}
	if err := validateCanonicalPolicyFields(defaults, "policy_database.client_defaults", "require_user_groups_from_policy", "refresh_tokens", "dpop", "require_par"); err != nil {
		return err
	}
	if err := rejectNullPolicyFields(defaults, "policy_database.client_defaults", "require_user_groups_from_policy", "refresh_tokens", "dpop", "require_par"); err != nil {
		return err
	}
	if dpopRaw, ok := defaults["dpop"]; ok {
		return validateDPoPFields(dpopRaw, "policy_database.client_defaults.dpop")
	}
	return nil
}

// validateDPoPFields rejects noncanonical or null DPoP object fields.
func validateDPoPFields(raw json.RawMessage, path string) error {
	dpop, err := decodePolicyObject(raw, path)
	if err != nil {
		return err
	}
	if err := validateCanonicalPolicyFields(dpop, path, "mode", "signing_algorithm"); err != nil {
		return err
	}
	return rejectNullPolicyFields(dpop, path, "mode", "signing_algorithm")
}

// validateUserGroupMappingFields rejects null maps and group lists.
func validateUserGroupMappingFields(raw json.RawMessage) error {
	mappings, err := decodePolicyObject(raw, "static_policy.user_group_mappings")
	if err != nil {
		return err
	}
	for name, mappingRaw := range mappings {
		path := "static_policy.user_group_mappings." + name
		mapping, err := decodePolicyObject(mappingRaw, path)
		if err != nil {
			return err
		}
		for subject, groups := range mapping {
			if bytes.Equal(bytes.TrimSpace(groups), []byte("null")) {
				return fmt.Errorf("%s.%s must not be null", path, subject)
			}
		}
	}
	return nil
}

// validateTrustPolicyFields rejects null trust policy properties while leaving claim schemas opaque.
func validateTrustPolicyFields(raw json.RawMessage) error {
	policies, err := decodePolicyObject(raw, "static_policy.trust_policies")
	if err != nil {
		return err
	}
	for name, policyRaw := range policies {
		path := "static_policy.trust_policies." + name
		policy, err := decodePolicyObject(policyRaw, path)
		if err != nil {
			return err
		}
		if err := validateCanonicalPolicyFields(policy, path, "issuer", "subject", "groups", "required_claims", "claims"); err != nil {
			return err
		}
		if err := rejectNullPolicyFields(policy, path, "issuer", "subject", "groups", "required_claims", "claims"); err != nil {
			return err
		}
	}
	return nil
}

// validateTrustBindingFields rejects null trust binding properties while leaving claim schemas opaque.
func validateTrustBindingFields(raw json.RawMessage, path string) error {
	var bindings []json.RawMessage
	if err := json.Unmarshal(raw, &bindings); err != nil {
		return fmt.Errorf("%s: decode entries: %w", path, err)
	}
	for i, bindingRaw := range bindings {
		bindingPath := fmt.Sprintf("%s[%d]", path, i)
		binding, err := decodePolicyObject(bindingRaw, bindingPath)
		if err != nil {
			return err
		}
		if err := validateCanonicalPolicyFields(binding, bindingPath, "id", "trust_policy", "subject", "groups", "claims"); err != nil {
			return err
		}
		if err := rejectNullPolicyFields(binding, bindingPath, "id", "trust_policy", "subject", "groups", "claims"); err != nil {
			return err
		}
	}
	return nil
}

// decodePolicyObject decodes a required policy object.
func decodePolicyObject(raw json.RawMessage, path string) (map[string]json.RawMessage, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("%s: decode fields: %w", path, err)
	}
	return fields, nil
}

// rejectNullPolicyFields rejects explicit null values for the named fields.
func rejectNullPolicyFields(fields map[string]json.RawMessage, path string, names ...string) error {
	for _, name := range names {
		if raw, present := fields[name]; present && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s.%s must not be null", path, name)
		}
	}
	return nil
}

// validateCanonicalPolicyFields rejects case-insensitive aliases accepted by encoding/json.
func validateCanonicalPolicyFields(fields map[string]json.RawMessage, path string, canonical ...string) error {
	for name := range fields {
		for _, expected := range canonical {
			if strings.EqualFold(name, expected) && name != expected {
				return fmt.Errorf("%s.%s must use its canonical field name", path, expected)
			}
		}
	}
	return nil
}

// validateStateDatabaseFields distinguishes omitted fields from explicit zero values.
func validateStateDatabaseFields(data []byte, database *StateDatabaseConfig) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("state_database: decode fields: %w", err)
	}
	for name := range document {
		if strings.EqualFold(name, "state_database") && name != "state_database" {
			return fmt.Errorf("state_database must use its canonical field name")
		}
	}
	raw, present := document["state_database"]
	if !present {
		return nil
	}
	if database == nil {
		return fmt.Errorf("state_database must be an object")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("state_database: decode fields: %w", err)
	}
	for name := range fields {
		switch name {
		case "connection_string_secret", "driver", "max_connections", "migrations", "path", "query_timeout":
		default:
			return fmt.Errorf("state_database: unknown field %q", name)
		}
	}
	has := func(name string) bool {
		_, ok := fields[name]
		return ok
	}
	if has("driver") && strings.TrimSpace(database.Driver) == "" {
		return fmt.Errorf("state_database: driver must not be empty")
	}
	driver := database.Driver
	if driver == "" {
		driver = "sqlite"
	}
	switch driver {
	case "sqlite":
		for _, field := range []string{"connection_string_secret", "max_connections", "query_timeout", "migrations"} {
			if has(field) {
				return fmt.Errorf("state_database: %s is not valid for sqlite", field)
			}
		}
		if has("path") && strings.TrimSpace(database.Path) == "" {
			return fmt.Errorf("state_database: path must not be empty")
		}
	case "postgresql":
		if has("path") {
			return fmt.Errorf("state_database: path is not valid for postgresql")
		}
		if has("max_connections") && database.MaxConnections <= 0 {
			return fmt.Errorf("state_database: max_connections must be positive")
		}
		if has("query_timeout") && database.QueryTimeout.Duration() <= 0 {
			return fmt.Errorf("state_database: query_timeout must be positive")
		}
		if migrationRaw, migrationPresent := fields["migrations"]; migrationPresent {
			if database.Migrations == nil {
				return fmt.Errorf("state_database: migrations must be an object")
			}
			var migrationFields map[string]json.RawMessage
			if err := json.Unmarshal(migrationRaw, &migrationFields); err != nil {
				return fmt.Errorf("state_database: decode migrations fields: %w", err)
			}
			for name := range migrationFields {
				if name != "connection_string_secret" {
					return fmt.Errorf("state_database: migrations: unknown field %q", name)
				}
			}
			if _, secretPresent := migrationFields["connection_string_secret"]; secretPresent && strings.TrimSpace(database.Migrations.ConnectionStringSecret) == "" {
				return fmt.Errorf("state_database: migrations.connection_string_secret must not be empty")
			}
		}
	}
	return nil
}

// applyDurationDefault applies a documented default only when the field was omitted.
func applyDurationDefault(value *Duration, fallback time.Duration) {
	if value.Duration() == 0 {
		*value = Duration(fallback)
	}
}

// applyRefreshDefaults fills omitted refresh lifetime fields.
func applyRefreshDefaults(policy *RefreshTokenConfig) {
	applyDurationDefault(&policy.SessionIdleTTL, 30*time.Minute)
	applyDurationDefault(&policy.SessionAbsoluteTTL, 10*time.Hour)
	applyDurationDefault(&policy.OfflineIdleTTL, 30*24*time.Hour)
	applyDurationDefault(&policy.OfflineAbsoluteTTL, 90*24*time.Hour)
}

func validate(cfg *Config) error {
	if err := validateIssuerURL(cfg.IssuerURL); err != nil {
		return fmt.Errorf("issuer_url: %w", err)
	}
	if cfg.HomepageURL != "" {
		if err := validateHomepageURL(cfg.HomepageURL); err != nil {
			return fmt.Errorf("homepage_url: %w", err)
		}
	}

	if cfg.HTTPListenAddr == "" {
		return fmt.Errorf("http_listen_addr is required")
	}
	if cfg.ServingCertificate != nil {
		if strings.TrimSpace(cfg.ServingCertificate.CertificateFile) == "" {
			return fmt.Errorf("serving_certificate.certificate_file is required")
		}
		if strings.TrimSpace(cfg.ServingCertificate.PrivateKeyFile) == "" {
			return fmt.Errorf("serving_certificate.private_key_file is required")
		}
	}

	if _, ok := supportedSigningAlgorithms[cfg.SigningAlgorithm]; !ok {
		return fmt.Errorf("signing_algorithm must be one of RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, or EdDSA")
	}

	if err := validateSecretsProvider(cfg.Secrets.Provider); err != nil {
		return fmt.Errorf("secrets.provider: %w", err)
	}

	if cfg.Secrets.SigningKeyName == "" {
		return fmt.Errorf("secrets.signing_key_name is required")
	}

	if cfg.Secrets.Provider == "azure" && cfg.Secrets.AzureKeyVaultURL == "" {
		return fmt.Errorf("secrets.azure_keyvault_url is required for Azure provider")
	}
	if cfg.Secrets.Provider == "file" && cfg.Secrets.FileDirectory == "" {
		return fmt.Errorf("secrets.file_directory is required for file provider")
	}

	if len(cfg.UserLoginConnectors) == 0 {
		return fmt.Errorf("at least one user login connector must be configured")
	}
	idPattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	hasEmailConnector := false
	needsEncryption := false
	refreshEnabled := cfg.PolicyDatabase != nil && cfg.PolicyDatabase.ClientDefaults.RefreshTokens.Enabled
	for _, client := range cfg.StaticPolicy.Clients {
		refreshEnabled = refreshEnabled || client.RefreshTokens.Enabled
	}
	for id, connector := range cfg.UserLoginConnectors {
		if !idPattern.MatchString(id) {
			return fmt.Errorf("connector ID %q is not path-safe", id)
		}
		if err := validateConnector(&connector); err != nil {
			return fmt.Errorf("connector %q: %w", id, err)
		}
		if connector.DisplayName == "" {
			return fmt.Errorf("connector %q: display_name is required", id)
		}
		if connector.Type == "email" {
			hasEmailConnector = true
		} else if connector.CredentialsSecret == "" {
			return fmt.Errorf("connector %q: credentials_secret is required", id)
		}
		needsEncryption = needsEncryption || connector.Type == "github" || (refreshEnabled && connector.Type != "email")
	}
	if needsEncryption && cfg.Secrets.EncryptionKeyName == "" {
		return fmt.Errorf("secrets.encryption_key_name is required when a refresh-enabled client can use a non-email connector")
	}
	if cfg.Email == nil {
		if hasEmailConnector {
			return fmt.Errorf("email configuration is required when an email connector is configured")
		}
	} else {
		if cfg.Email.VerificationMode != "disabled" && cfg.Email.VerificationMode != "provider" && cfg.Email.VerificationMode != "strict" {
			return fmt.Errorf("email.verification_mode must be disabled, provider, or strict")
		}
		needsEmailDelivery := hasEmailConnector || cfg.Email.VerificationMode == "provider" || cfg.Email.VerificationMode == "strict"
		if needsEmailDelivery && cfg.Email.OTPSecretName == "" {
			return fmt.Errorf("email.otp_secret_name is required when email verification can occur")
		}
		if needsEmailDelivery && cfg.Email.SMTP == nil {
			return fmt.Errorf("complete email.smtp configuration is required")
		}
		otpTTL := cfg.Email.OTPTTL.Duration()
		if needsEmailDelivery && (otpTTL < time.Minute || otpTTL > 10*time.Minute || otpTTL%time.Minute != 0) {
			return fmt.Errorf("email.otp_ttl must be a whole number of minutes from 1m through 10m")
		}
		if cfg.Email.SMTP != nil {
			smtp := cfg.Email.SMTP
			if smtp.Host == "" || smtp.Port < 1 || smtp.Port > 65535 || smtp.FromAddress == "" {
				return fmt.Errorf("complete email.smtp configuration is required")
			}
			from, err := mail.ParseAddress(smtp.FromAddress)
			if err != nil || from.Address != smtp.FromAddress {
				return fmt.Errorf("email.smtp.from_address must be a bare email address")
			}
			if smtp.TLSMode == "" {
				smtp.TLSMode = "starttls"
			}
			if smtp.TLSMode != "starttls" && smtp.TLSMode != "implicit" && smtp.TLSMode != "plaintext" {
				return fmt.Errorf("email.smtp.tls_mode must be starttls, implicit, or plaintext")
			}
			if smtp.TLSMode == "plaintext" && smtp.Host != "localhost" {
				return fmt.Errorf("email.smtp.tls_mode plaintext is only permitted when host is localhost")
			}
		}
		if cfg.Email.Turnstile != nil {
			if (cfg.Email.Turnstile.SiteKey == "") != (cfg.Email.Turnstile.SecretName == "") {
				return fmt.Errorf("email.turnstile site_key and secret_name must be set together")
			}
			if remoteIP := cfg.Email.Turnstile.RemoteIP; remoteIP != nil {
				switch remoteIP.Source {
				case "remote_addr":
					if remoteIP.Header != "" {
						return fmt.Errorf("email.turnstile.remote_ip.header is only valid for the header source")
					}
				case "header":
					if !regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").MatchString(remoteIP.Header) {
						return fmt.Errorf("email.turnstile.remote_ip.header must be a valid HTTP header name")
					}
					remoteIP.Header = textproto.CanonicalMIMEHeaderKey(remoteIP.Header)
				default:
					return fmt.Errorf("email.turnstile.remote_ip.source must be remote_addr or header")
				}
			}
		}
	}

	if clients := cfg.StaticPolicy.Clients; clients != nil && len(clients) == 0 {
		return fmt.Errorf("static_policy.clients must not be empty")
	}
	if defaults := cfg.StaticPolicy.DefaultRedirectURIs; defaults != nil {
		if len(defaults) == 0 {
			return fmt.Errorf("static_policy.default_redirect_uris must not be empty")
		}
		for _, redirect := range defaults {
			if err := validateRedirectURI(redirect); err != nil {
				return fmt.Errorf("static_policy.default_redirect_uris: %w", err)
			}
		}
	}
	if len(cfg.StaticPolicy.Clients) == 0 && cfg.PolicyDatabase == nil {
		return fmt.Errorf("static_policy.clients or policy_database must configure at least one client")
	}
	if database := cfg.PolicyDatabase; database != nil {
		if err := validatePolicyDatabase(database); err != nil {
			return fmt.Errorf("policy_database: %w", err)
		}
	}
	if database := cfg.StateDatabase; database != nil {
		if err := validateStateDatabase(database); err != nil {
			return fmt.Errorf("state_database: %w", err)
		}
	}
	for clientID, client := range cfg.StaticPolicy.Clients {
		if client.RefreshTokens.AllowOfflineAccess && !client.RefreshTokens.Enabled {
			return fmt.Errorf("client %q: refresh_tokens.allow_offline_access requires refresh_tokens.enabled", clientID)
		}
		if client.RefreshTokens.SessionIdleTTL.Duration() > client.RefreshTokens.SessionAbsoluteTTL.Duration() {
			return fmt.Errorf("client %q: refresh_tokens.session_idle_ttl must not exceed session_absolute_ttl", clientID)
		}
		if client.RefreshTokens.OfflineIdleTTL.Duration() > client.RefreshTokens.OfflineAbsoluteTTL.Duration() {
			return fmt.Errorf("client %q: refresh_tokens.offline_idle_ttl must not exceed offline_absolute_ttl", clientID)
		}
		if err := validateClient(clientID, client, cfg.StaticPolicy.DefaultRedirectURIs, cfg.StaticPolicy.UserGroupMappings); err != nil {
			return fmt.Errorf("client %q: %w", clientID, err)
		}
	}

	if err := validateUserGroupMappings(cfg.StaticPolicy.UserGroupMappings); err != nil {
		return fmt.Errorf("static_policy.user_group_mappings: %w", err)
	}
	if err := validateTrust(cfg); err != nil {
		return fmt.Errorf("trust configuration: %w", err)
	}

	return nil
}

// validateStateDatabase validates the effective state database configuration.
func validateStateDatabase(database *StateDatabaseConfig) error {
	switch database.Driver {
	case "sqlite":
		if strings.TrimSpace(database.Path) == "" {
			return fmt.Errorf("path is required for sqlite")
		}
		if database.ConnectionStringSecret != "" || database.MaxConnections != 0 || database.QueryTimeout != 0 || database.Migrations != nil {
			return fmt.Errorf("PostgreSQL settings are not valid for sqlite")
		}
	case "postgresql":
		if database.Path != "" {
			return fmt.Errorf("path is not valid for postgresql")
		}
		if strings.TrimSpace(database.ConnectionStringSecret) == "" {
			return fmt.Errorf("connection_string_secret is required for postgresql")
		}
		if database.MaxConnections <= 0 {
			return fmt.Errorf("max_connections must be positive")
		}
		if database.QueryTimeout.Duration() <= 0 {
			return fmt.Errorf("query_timeout must be positive")
		}
		if database.Migrations != nil && database.Migrations.ConnectionStringSecret != "" && strings.TrimSpace(database.Migrations.ConnectionStringSecret) == "" {
			return fmt.Errorf("migrations.connection_string_secret must not be blank")
		}
	default:
		return fmt.Errorf("driver must be sqlite or postgresql")
	}
	return nil
}

// validatePolicyDatabase validates all limits and settings known before its secret is loaded.
func validatePolicyDatabase(policyDatabase *PolicyDatabaseConfig) error {
	if policyDatabase.Driver != "postgresql" {
		return fmt.Errorf("driver must be postgresql")
	}
	if strings.TrimSpace(policyDatabase.ConnectionStringSecret) == "" {
		return fmt.Errorf("connection_string_secret is required")
	}
	if len(policyDatabase.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris must not be empty")
	}
	for _, redirect := range policyDatabase.RedirectURIs {
		if err := validateRedirectURI(redirect); err != nil {
			return fmt.Errorf("redirect_uris: %w", err)
		}
	}
	if policyDatabase.ClientDefaults.RefreshTokens.AllowOfflineAccess && !policyDatabase.ClientDefaults.RefreshTokens.Enabled {
		return fmt.Errorf("client_defaults.refresh_tokens.allow_offline_access requires enabled")
	}
	if err := validateDPoP(policyDatabase.ClientDefaults.DPoP); err != nil {
		return fmt.Errorf("client_defaults: %w", err)
	}
	r := policyDatabase.ClientDefaults.RefreshTokens
	if r.SessionIdleTTL.Duration() > r.SessionAbsoluteTTL.Duration() || r.OfflineIdleTTL.Duration() > r.OfflineAbsoluteTTL.Duration() {
		return fmt.Errorf("client_defaults refresh idle TTL must not exceed absolute TTL")
	}
	if policyDatabase.QueryTimeout.Duration() < 10*time.Millisecond || policyDatabase.QueryTimeout.Duration() > 30*time.Second {
		return fmt.Errorf("query_timeout must be between 10ms and 30s")
	}
	if policyDatabase.ClientLookupCache.TTL.Duration() > time.Hour || policyDatabase.ClientLookupCache.NegativeTTL.Duration() > time.Hour {
		return fmt.Errorf("client lookup cache TTLs must not exceed 1h")
	}
	if policyDatabase.ClientLookupCache.MaxEntries < 1 || policyDatabase.ClientLookupCache.MaxEntries > 100000 || policyDatabase.PolicyBuildCache.MaxEntries < 1 || policyDatabase.PolicyBuildCache.MaxEntries > 100000 {
		return fmt.Errorf("cache max_entries must be between 1 and 100000")
	}
	if policyDatabase.MaxConnections < 1 || policyDatabase.MaxConnections > 32 {
		return fmt.Errorf("max_connections must be between 1 and 32")
	}
	if policyDatabase.MaxTrustRows < 1 || policyDatabase.MaxTrustRows > 1000 || policyDatabase.MaxGroups < 1 || policyDatabase.MaxGroups > 1000 || policyDatabase.MaxGroupBytes < 1 || policyDatabase.MaxGroupBytes > 4096 || policyDatabase.MaxJSONBytes < 1024 || policyDatabase.MaxJSONBytes > 1<<20 {
		return fmt.Errorf("result limits are outside safe bounds")
	}
	return nil
}

func validateIssuerURL(issuer string) error {
	if issuer == "" {
		return fmt.Errorf("is required")
	}

	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("must be absolute and include a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not contain userinfo, query, or fragment")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme must be http or https")
	}

	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return fmt.Errorf("http scheme only allowed for localhost in development")
	}

	return nil
}

// validateHomepageURL requires an absolute public web URL without embedded credentials.
func validateHomepageURL(homepage string) error {
	u, err := url.Parse(homepage)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("must be absolute and include a host")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain userinfo")
	}
	if u.Scheme == "http" {
		if u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
			return fmt.Errorf("http scheme only allowed for localhost in development")
		}
	} else if u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	return nil
}

func validateSecretsProvider(provider string) error {
	valid := map[string]bool{"aws-secrets-manager": true, "aws-parameter-store": true, "google-secret-manager": true, "azure": true, "env": true, "file": true}
	if !valid[provider] {
		return fmt.Errorf("must be one of: aws-secrets-manager, aws-parameter-store, google-secret-manager, azure, env, file")
	}
	return nil
}

func validateConnector(c *ConnectorConfig) error {
	if c.Type != "google" && c.Type != "github" && c.Type != "generic" && c.Type != "email" {
		return fmt.Errorf("type must be google, github, generic, or email")
	}

	if c.Type == "generic" {
		if c.Generic == nil {
			return fmt.Errorf("generic configuration is required for type generic")
		}
		if c.Generic.AuthorizationURL == "" {
			return fmt.Errorf("generic.authorization_url is required")
		}
		if c.Generic.TokenURL == "" {
			return fmt.Errorf("generic.token_url is required")
		}
		if c.Generic.UserinfoURL == "" {
			return fmt.Errorf("generic.userinfo_url is required")
		}
		if _, err := url.Parse(c.Generic.AuthorizationURL); err != nil {
			return fmt.Errorf("generic.authorization_url is not a valid URL: %w", err)
		}
		if _, err := url.Parse(c.Generic.TokenURL); err != nil {
			return fmt.Errorf("generic.token_url is not a valid URL: %w", err)
		}
		if _, err := url.Parse(c.Generic.UserinfoURL); err != nil {
			return fmt.Errorf("generic.userinfo_url is not a valid URL: %w", err)
		}
		if c.Generic.Refresh != nil {
			owned := map[string]bool{"client_id": true, "redirect_uri": true, "response_type": true, "scope": true, "state": true, "nonce": true, "code_challenge": true, "code_challenge_method": true}
			for key := range c.Generic.Refresh.AuthorizationParams {
				if owned[key] {
					return fmt.Errorf("generic.refresh.authorization_params may not set Truster-owned parameter %q", key)
				}
				if key == "" {
					return fmt.Errorf("generic.refresh.authorization_params keys must not be empty")
				}
			}
			for _, scope := range c.Generic.Refresh.Scopes {
				if strings.TrimSpace(scope) == "" || strings.ContainsAny(scope, " \t\r\n") {
					return fmt.Errorf("generic.refresh.scopes must contain nonempty individual scope values")
				}
			}
		}
	}

	return nil
}

func validateClient(clientID string, c ClientConfig, defaultRedirectURIs []string, mappings map[string]map[string][]string) error {
	if clientID == "" {
		return fmt.Errorf("client_id cannot be empty")
	}

	redirectURIs := c.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = defaultRedirectURIs
	}

	if len(redirectURIs) == 0 {
		return fmt.Errorf("redirect_uris must be specified either per-client or as default_redirect_uris")
	}

	for _, uri := range redirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			return fmt.Errorf("invalid redirect_uri %q: %w", uri, err)
		}
	}

	if c.UserGroupMapping != "" {
		if _, exists := mappings[c.UserGroupMapping]; !exists {
			return fmt.Errorf("user_group_mapping %q not found in user_group_mappings", c.UserGroupMapping)
		}
	}
	if err := validateDPoP(c.DPoP); err != nil {
		return err
	}

	return nil
}

// PublicEndpointURL builds an externally visible endpoint solely from a validated issuer.
func PublicEndpointURL(issuer, endpoint string) string {
	return strings.TrimRight(issuer, "/") + "/" + strings.TrimLeft(endpoint, "/")
}

// applyDPoPDefaults fills the secure client DPoP defaults.
func applyDPoPDefaults(dpop *DPoPConfig) {
	if dpop.Mode == "" {
		dpop.Mode = "disabled"
	}
	if dpop.Mode == "required" && dpop.SigningAlgorithm == "" {
		dpop.SigningAlgorithm = "ES256"
	}
}

// validateDPoP validates the closed, currently implemented client proof profiles.
func validateDPoP(dpop DPoPConfig) error {
	if dpop.Mode == "" {
		dpop.Mode = "disabled"
	}
	if dpop.Mode != "disabled" && dpop.Mode != "required" {
		return fmt.Errorf("dpop.mode must be disabled or required")
	}
	if dpop.Mode == "disabled" {
		if dpop.SigningAlgorithm != "" {
			return fmt.Errorf("dpop.signing_algorithm requires mode required")
		}
		return nil
	}
	if dpop.SigningAlgorithm == "" {
		dpop.SigningAlgorithm = "ES256"
	}
	if dpop.SigningAlgorithm != "ES256" && dpop.SigningAlgorithm != "ES512" {
		return fmt.Errorf("dpop.signing_algorithm must be ES256 or ES512")
	}
	return nil
}

func validateRedirectURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}

	if u.Scheme == "http" {
		if u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			return fmt.Errorf("http redirect URIs only allowed for localhost")
		}
	} else if u.Scheme != "https" {
		return fmt.Errorf("scheme must be http (localhost only) or https")
	}

	return nil
}

func validateUserGroupMappings(mappings map[string]map[string][]string) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	for mappingName, mapping := range mappings {
		if mappingName == "" {
			return fmt.Errorf("mapping key cannot be empty")
		}

		for email := range mapping {
			if !emailRegex.MatchString(email) {
				return fmt.Errorf("invalid email format in mapping %q: %q", mappingName, email)
			}
		}
	}

	return nil
}
