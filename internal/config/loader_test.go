// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "empty path",
			path:        "",
			expectError: true,
		},
		{
			name:        "non-existent file",
			path:        "/tmp/nonexistent-config-12345.jsonc",
			expectError: true,
		},
		{
			name:        "valid config",
			path:        "testdata/valid-config.jsonc",
			expectError: false,
		},
		{
			name:        "invalid json",
			path:        "testdata/invalid-json.jsonc",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "valid config" {
				setupTestConfig(t)
				defer cleanupTestConfig(t)
			}
			if tt.name == "invalid json" {
				setupInvalidConfig(t)
				defer cleanupTestConfig(t)
			}

			cfg, err := Load(tt.path)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
			if tt.name == "valid config" && cfg.SigningAlgorithm != DefaultSigningAlgorithm {
				t.Errorf("signing algorithm = %q, want %q", cfg.SigningAlgorithm, DefaultSigningAlgorithm)
			}
			if tt.name == "valid config" {
				if cfg.Email == nil {
					t.Error("email configuration was not loaded")
				} else if cfg.Email.VerificationMode != "disabled" {
					t.Errorf("email verification mode = %q, want disabled", cfg.Email.VerificationMode)
				}
			}
		})
	}
}

// TestLoadRejectsUnknownFields ensures configuration typos fail closed.
func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.jsonc")
	data := []byte(`{
		"issuer_url": "https://auth.example.com",
		"http_listen_addr": "127.0.0.1:8080",
		"data_dir": "data"
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("configuration with unknown field was accepted")
	}
}

func TestValidateIssuerURL(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		expectError bool
	}{
		{"valid https", "https://auth.example.com", false},
		{"valid https with port", "https://auth.example.com:8443", false},
		{"valid localhost http", "http://localhost:8080", false},
		{"valid 127.0.0.1 http", "http://127.0.0.1:8080", false},
		{"invalid http for production", "http://auth.example.com", true},
		{"invalid localhost suffix", "http://localhost.example.com", true},
		{"invalid localhost userinfo", "http://localhost@auth.example.com", true},
		{"empty issuer", "", true},
		{"invalid scheme", "ftp://auth.example.com", true},
		{"no scheme", "auth.example.com", true},
		{"invalid url", "://invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIssuerURL(tt.issuer)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		expectError bool
	}{
		{"valid https", "https://app.example.com/callback", false},
		{"valid https with port", "https://app.example.com:8443/callback", false},
		{"valid localhost http", "http://localhost:8000", false},
		{"valid localhost with path", "http://localhost:8000/callback", false},
		{"valid 127.0.0.1 http", "http://127.0.0.1:8000", false},
		{"invalid http for production", "http://app.example.com/callback", true},
		{"invalid localhost suffix", "http://localhost.example.com/callback", true},
		{"invalid localhost userinfo", "http://localhost@app.example.com/callback", true},
		{"invalid scheme", "ftp://localhost:8000", true},
		{"no scheme", "localhost:8000", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRedirectURI(tt.uri)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateSecretsProvider(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		expectError bool
	}{
		{"valid AWS Secrets Manager", "aws-secrets-manager", false},
		{"valid AWS Parameter Store", "aws-parameter-store", false},
		{"valid Google Secret Manager", "google-secret-manager", false},
		{"valid azure", "azure", false},
		{"valid env", "env", false},
		{"valid file", "file", false},
		{"unreleased filesystem name", "filesystem", true},
		{"old aws name", "aws", true},
		{"old gcp name", "gcp", true},
		{"invalid provider", "vault", true},
		{"empty provider", "", true},
		{"uppercase", "AWS", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecretsProvider(tt.provider)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateConnector(t *testing.T) {
	tests := []struct {
		name        string
		connector   ConnectorConfig
		expectError bool
	}{
		{
			name: "valid google",
			connector: ConnectorConfig{
				Type: "google",
			},
			expectError: false,
		},
		{
			name: "valid github",
			connector: ConnectorConfig{
				Type: "github",
			},
			expectError: false,
		},
		{
			name: "invalid type",
			connector: ConnectorConfig{
				Type: "okta",
			},
			expectError: true,
		},
		{
			name: "valid generic",
			connector: ConnectorConfig{
				Type: "generic",
				Generic: &GenericConfig{
					AuthorizationURL: "https://dex.example.com/auth",
					TokenURL:         "https://dex.example.com/token",
					UserinfoURL:      "https://dex.example.com/userinfo",
				},
			},
			expectError: false,
		},
		{
			name: "generic missing config",
			connector: ConnectorConfig{
				Type: "generic",
			},
			expectError: true,
		},
		{
			name: "generic missing authorization_url",
			connector: ConnectorConfig{
				Type: "generic",
				Generic: &GenericConfig{
					TokenURL:    "https://dex.example.com/token",
					UserinfoURL: "https://dex.example.com/userinfo",
				},
			},
			expectError: true,
		},
		{
			name: "generic missing token_url",
			connector: ConnectorConfig{
				Type: "generic",
				Generic: &GenericConfig{
					AuthorizationURL: "https://dex.example.com/auth",
					UserinfoURL:      "https://dex.example.com/userinfo",
				},
			},
			expectError: true,
		},
		{
			name: "generic missing userinfo_url",
			connector: ConnectorConfig{
				Type: "generic",
				Generic: &GenericConfig{
					AuthorizationURL: "https://dex.example.com/auth",
					TokenURL:         "https://dex.example.com/token",
				},
			},
			expectError: true,
		},
		{
			name: "generic invalid authorization_url",
			connector: ConnectorConfig{
				Type: "generic",
				Generic: &GenericConfig{
					AuthorizationURL: "://invalid",
					TokenURL:         "https://dex.example.com/token",
					UserinfoURL:      "https://dex.example.com/userinfo",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnector(&tt.connector)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateClient(t *testing.T) {
	defaultRedirects := []string{"http://localhost:8000"}
	mappings := map[string]map[string][]string{
		"test-groups": {
			"alice@example.com": {"admins"},
		},
	}

	tests := []struct {
		name        string
		clientID    string
		client      ClientConfig
		expectError bool
	}{
		{
			name:     "valid with redirect URIs",
			clientID: "test-client",
			client: ClientConfig{
				RedirectURIs: []string{"https://app.example.com/callback"},
			},
			expectError: false,
		},
		{
			name:        "valid with defaults",
			clientID:    "test-client",
			client:      ClientConfig{},
			expectError: false,
		},
		{
			name:     "valid with user group mapping",
			clientID: "test-client",
			client: ClientConfig{
				UserGroupMapping: "test-groups",
			},
			expectError: false,
		},
		{
			name:     "invalid user group mapping",
			clientID: "test-client",
			client: ClientConfig{
				UserGroupMapping: "nonexistent",
			},
			expectError: true,
		},
		{
			name:     "invalid redirect URI",
			clientID: "test-client",
			client: ClientConfig{
				RedirectURIs: []string{"ftp://invalid"},
			},
			expectError: true,
		},
		{
			name:        "empty client ID",
			clientID:    "",
			client:      ClientConfig{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClient(tt.clientID, tt.client, defaultRedirects, mappings)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateUserGroupMappings(t *testing.T) {
	tests := []struct {
		name        string
		mappings    map[string]map[string][]string
		expectError bool
	}{
		{
			name: "valid mappings",
			mappings: map[string]map[string][]string{
				"prod-groups": {
					"alice@example.com": {"admins"},
					"bob@example.com":   {"users"},
				},
			},
			expectError: false,
		},
		{
			name: "invalid email format",
			mappings: map[string]map[string][]string{
				"prod-groups": {
					"not-an-email": {"admins"},
				},
			},
			expectError: true,
		},
		{
			name: "empty mapping name",
			mappings: map[string]map[string][]string{
				"": {
					"alice@example.com": {"admins"},
				},
			},
			expectError: true,
		},
		{
			name: "complex emails",
			mappings: map[string]map[string][]string{
				"groups": {
					"alice+tag@example.com":     {"admins"},
					"bob.smith@sub.example.com": {"users"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUserGroupMappings(tt.mappings)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid minimal config",
			config: Config{
				IssuerURL:        "https://auth.example.com",
				HTTPListenAddr:   "127.0.0.1:8080",
				SigningAlgorithm: DefaultSigningAlgorithm,
				JWKSKID:          "key-1",
				Secrets: SecretsConfig{
					Provider:       "env",
					SigningKeyName: "SIGNING_KEY",
				},
				UserLoginConnectors: map[string]ConnectorConfig{
					"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "GOOGLE_CREDS"},
				},
				StaticPolicy: StaticPolicyConfig{
					DefaultRedirectURIs: []string{"http://localhost:8000"},
					Clients:             map[string]ClientConfig{"test-client": {}},
				},
			},
			expectError: false,
		},
		{
			name: "invalid signing algorithm",
			config: Config{
				IssuerURL:        "https://auth.example.com",
				HTTPListenAddr:   "127.0.0.1:8080",
				SigningAlgorithm: "HS256",
			},
			expectError: true,
		},
		{
			name: "missing issuer_url",
			config: Config{
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
			},
			expectError: true,
		},
		{
			name: "missing http_listen_addr",
			config: Config{
				IssuerURL: "https://auth.example.com",
				JWKSKID:   "key-1",
			},
			expectError: true,
		},
		{
			name: "missing jwks_kid",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
			},
			expectError: true,
		},
		{
			name: "invalid secrets provider",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider: "invalid",
				},
			},
			expectError: true,
		},
		{
			name: "AWS Secrets Manager without secret names",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider: "aws-secrets-manager",
				},
			},
			expectError: true,
		},
		{
			name: "azure without vault url",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider:       "azure",
					SigningKeyName: "key",
				},
			},
			expectError: true,
		},
		{
			name: "file without directory",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider:       "file",
					SigningKeyName: "key",
				},
			},
			expectError: true,
		},
		{
			name: "no clients",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider:       "env",
					SigningKeyName: "SIGNING_KEY",
				},
				UserLoginConnectors: map[string]ConnectorConfig{
					"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "GOOGLE_CREDS"},
				},
				StaticPolicy: StaticPolicyConfig{Clients: map[string]ClientConfig{}},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(&tt.config)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v (error: %v)", tt.expectError, err != nil, err)
			}
		})
	}
}

// TestValidateServingCertificate verifies that native HTTPS is optional but complete when configured.
func TestValidateServingCertificate(t *testing.T) {
	base := Config{
		IssuerURL: "https://auth.example.com", HTTPListenAddr: "127.0.0.1:8080",
		SigningAlgorithm: DefaultSigningAlgorithm, JWKSKID: "key-1",
		Secrets:             SecretsConfig{Provider: "env", SigningKeyName: "SIGNING_KEY"},
		UserLoginConnectors: map[string]ConnectorConfig{"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "CREDS"}},
		StaticPolicy:        StaticPolicyConfig{DefaultRedirectURIs: []string{"http://localhost:8000"}, Clients: map[string]ClientConfig{"client": {}}},
	}
	for _, test := range []struct {
		name        string
		certificate *ServingCertificateConfig
		valid       bool
	}{
		{"omitted", nil, true},
		{"complete", &ServingCertificateConfig{CertificateFile: "/cert/tls.crt", PrivateKeyFile: "/cert/tls.key"}, true},
		{"empty object", &ServingCertificateConfig{}, false},
		{"missing certificate", &ServingCertificateConfig{PrivateKeyFile: "/cert/tls.key"}, false},
		{"missing private key", &ServingCertificateConfig{CertificateFile: "/cert/tls.crt"}, false},
		{"whitespace paths", &ServingCertificateConfig{CertificateFile: " ", PrivateKeyFile: "\t"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			cfg.ServingCertificate = test.certificate
			if err := validate(&cfg); (err == nil) != test.valid {
				t.Fatalf("validate() error = %v, want valid = %v", err, test.valid)
			}
		})
	}
}

// validTestConfig returns a minimal valid configuration.
func validTestConfig() Config {
	return Config{
		IssuerURL:        "https://auth.example.com",
		HTTPListenAddr:   "127.0.0.1:8080",
		SigningAlgorithm: "RS256",
		Secrets: SecretsConfig{
			Provider:       "env",
			SigningKeyName: "TRUSTER_SIGNING_KEY",
		},
		UserLoginConnectors: map[string]ConnectorConfig{
			"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "TRUSTER_GOOGLE_CREDENTIALS"},
		},
		StaticPolicy: StaticPolicyConfig{
			Clients: map[string]ClientConfig{"client": {RedirectURIs: []string{"https://client.example.com/callback"}}},
		},
	}
}

// TestDPoPDefaultsAndValidation verifies the closed per-client proof profiles.
func TestDPoPDefaultsAndValidation(t *testing.T) {
	required := DPoPConfig{Mode: "required"}
	applyDPoPDefaults(&required)
	if required.SigningAlgorithm != "ES256" || validateDPoP(required) != nil {
		t.Fatalf("required defaults = %#v", required)
	}
	if err := validateDPoP(DPoPConfig{Mode: "required", SigningAlgorithm: "ES512"}); err != nil {
		t.Fatalf("ES512 rejected: %v", err)
	}
	for _, invalid := range []DPoPConfig{
		{Mode: "optional"},
		{Mode: "required", SigningAlgorithm: "ES384"},
		{Mode: "disabled", SigningAlgorithm: "ES512"},
	} {
		if err := validateDPoP(invalid); err == nil {
			t.Fatalf("accepted invalid DPoP configuration: %#v", invalid)
		}
	}
}

// validEmailConfig returns a complete email verification configuration.
func validEmailConfig() *EmailConfig {
	return &EmailConfig{
		VerificationMode: "provider",
		OTPSecretName:    "TRUSTER_OTP_SECRET",
		OTPTTL:           Duration(5 * time.Minute),
		SMTP: &SMTPConfig{
			Host:              "smtp.example.com",
			Port:              587,
			FromAddress:       "auth@example.com",
			CredentialsSecret: "TRUSTER_SMTP_CREDENTIALS",
		},
	}
}

// TestValidateEmailConfiguration verifies email configuration validation.
func TestValidateEmailConfiguration(t *testing.T) {
	cfg := validTestConfig()
	cfg.UserLoginConnectors["email"] = ConnectorConfig{Type: "email", DisplayName: "Email"}
	if err := validate(&cfg); err == nil {
		t.Fatal("email connector accepted without email configuration")
	}
	cfg.Email = validEmailConfig()
	if err := validate(&cfg); err != nil {
		t.Fatalf("valid email configuration rejected: %v", err)
	}
	if cfg.Email.SMTP.TLSMode != "starttls" {
		t.Fatalf("TLS mode = %q, want starttls", cfg.Email.SMTP.TLSMode)
	}
	cfg.Email.SMTP.Host = "localhost"
	cfg.Email.SMTP.TLSMode = "plaintext"
	if err := validate(&cfg); err != nil {
		t.Fatalf("plaintext SMTP mode rejected: %v", err)
	}
	cfg.Email.SMTP.CredentialsSecret = ""
	if err := validate(&cfg); err != nil {
		t.Fatalf("unauthenticated SMTP rejected: %v", err)
	}
	cfg.Email.SMTP.Host = "smtp.example.com"
	if err := validate(&cfg); err == nil {
		t.Fatal("plaintext SMTP accepted for a non-localhost server")
	}
	cfg.Email.SMTP.Host = "localhost"
	cfg.Email.SMTP.TLSMode = "invalid"
	if err := validate(&cfg); err == nil {
		t.Fatal("invalid SMTP TLS mode accepted")
	}
	cfg.Email.SMTP.TLSMode = "starttls"
	cfg.Email.OTPTTL = Duration(30 * time.Second)
	if err := validate(&cfg); err == nil {
		t.Fatal("unsafe OTP validity accepted")
	}
	cfg.Email.OTPTTL = Duration(5 * time.Minute)
	cfg.Email.Turnstile = &TurnstileConfig{SiteKey: "site-only"}
	if err := validate(&cfg); err == nil {
		t.Fatal("partial Turnstile configuration accepted")
	}
	cfg.Email.Turnstile = &TurnstileConfig{SiteKey: "site", SecretName: "secret", RemoteIP: &TurnstileRemoteIPConfig{Source: "header", Header: "invalid header"}}
	if err := validate(&cfg); err == nil {
		t.Fatal("invalid Turnstile remote IP header accepted")
	}
	cfg.Email.Turnstile.RemoteIP.Header = "cf-connecting-ip"
	if err := validate(&cfg); err != nil {
		t.Fatalf("valid Turnstile remote IP header rejected: %v", err)
	}
	if cfg.Email.Turnstile.RemoteIP.Header != "Cf-Connecting-Ip" {
		t.Fatalf("Turnstile remote IP header = %q, want canonical name", cfg.Email.Turnstile.RemoteIP.Header)
	}
	cfg.Email.Turnstile.RemoteIP = &TurnstileRemoteIPConfig{Source: "remote_addr", Header: "X-Forwarded-For"}
	if err := validate(&cfg); err == nil {
		t.Fatal("Turnstile remote_addr source accepted a header")
	}
	cfg.Email.Turnstile.RemoteIP = &TurnstileRemoteIPConfig{Source: "remote_addr"}
	if err := validate(&cfg); err != nil {
		t.Fatalf("valid Turnstile remote_addr source rejected: %v", err)
	}

	disabled := validTestConfig()
	disabled.Email = &EmailConfig{VerificationMode: "disabled"}
	if err := validate(&disabled); err != nil {
		t.Fatalf("disabled verification without SMTP rejected: %v", err)
	}
	disabled.Email.SMTP = &SMTPConfig{Host: "smtp.example.com"}
	if err := validate(&disabled); err == nil {
		t.Fatal("partial optional SMTP configuration accepted")
	}

	provider := validTestConfig()
	provider.Email = &EmailConfig{VerificationMode: "provider", OTPTTL: Duration(5 * time.Minute)}
	if err := validate(&provider); err == nil {
		t.Fatal("provider verification accepted without OTP and SMTP configuration")
	}
}

// TestValidateConnectorID verifies connector IDs must be path-safe.
func TestValidateConnectorID(t *testing.T) {
	cfg := validTestConfig()
	cfg.UserLoginConnectors["not/safe"] = cfg.UserLoginConnectors["google"]
	delete(cfg.UserLoginConnectors, "google")
	if err := validate(&cfg); err == nil {
		t.Fatal("unsafe connector ID accepted")
	}
}

// TestValidateGitHubRequiresEncryptionKey verifies multi-email selection requires encryption.
func TestValidateGitHubRequiresEncryptionKey(t *testing.T) {
	cfg := validTestConfig()
	cfg.UserLoginConnectors["github"] = ConnectorConfig{Type: "github", DisplayName: "GitHub", CredentialsSecret: "TRUSTER_GITHUB_CREDENTIALS"}
	delete(cfg.UserLoginConnectors, "google")
	if err := validate(&cfg); err == nil {
		t.Fatal("GitHub connector accepted without an encryption key")
	}
	cfg.Secrets.EncryptionKeyName = "TRUSTER_ENCRYPTION_KEY"
	if err := validate(&cfg); err != nil {
		t.Fatalf("GitHub connector with encryption key rejected: %v", err)
	}
}

// Helper functions for test setup

func setupTestConfig(t *testing.T) {
	t.Helper()
	testDir := "testdata"
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	configContent := `{
		// JSONC comments and trailing commas are supported.
		"issuer_url": "https://auth.example.com",
		"http_listen_addr": "127.0.0.1:8080",
		"jwks_kid": "test-key",
		"secrets": {
			"provider": "env",
			"signing_key_name": "SIGNING_KEY"
		},
		"email": {},
		"user_login_connectors": {
			"google": {"type": "google", "display_name": "Google", "credentials_secret": "GOOGLE_CREDS"}
		},
		"static_policy": {
			"default_redirect_uris": ["http://localhost:8000"],
			"clients": {
				"test-client": {},
			},
		},
	}`

	if err := os.WriteFile(filepath.Join(testDir, "valid-config.jsonc"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}
}

func setupInvalidConfig(t *testing.T) {
	t.Helper()
	testDir := "testdata"
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(testDir, "invalid-json.jsonc"), []byte("{invalid json"), 0644); err != nil {
		t.Fatal(err)
	}
}

func cleanupTestConfig(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll("testdata"); err != nil {
		t.Logf("failed to remove testdata: %v", err)
	}
}
