// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tailscale/hujson"
)

const configSchemaID = "https://truster.dev/schema/v2/config.schema.json"

// TestExampleConfigs validates every example against both the v2 JSON Schema
// and the application's authoritative configuration loader.
func TestExampleConfigs(t *testing.T) {
	compiledSchema := compileConfigSchema(t)

	examples, err := filepath.Glob(filepath.Join("..", "..", "examples", "config", "*.jsonc"))
	if err != nil {
		t.Fatalf("find example configurations: %v", err)
	}
	if len(examples) == 0 {
		t.Fatal("no example configurations found")
	}

	t.Setenv("TRUSTER_TEMPLATES_DIR", "")
	for _, examplePath := range examples {
		t.Run(filepath.Base(examplePath), func(t *testing.T) {
			data, readErr := os.ReadFile(examplePath)
			if readErr != nil {
				t.Fatalf("read example: %v", readErr)
			}
			instance := parseJSONCInstance(t, data)
			if validateErr := compiledSchema.Validate(instance); validateErr != nil {
				t.Errorf("schema validation failed: %v", validateErr)
			}
			if _, loadErr := Load(examplePath); loadErr != nil {
				t.Errorf("application validation failed: %v", loadErr)
			}
		})
	}
}

// TestConfigSchemaContracts verifies conditional and cross-field constraints
// that cannot be demonstrated by valid examples alone.
func TestConfigSchemaContracts(t *testing.T) {
	compiledSchema := compileConfigSchema(t)
	base := map[string]any{
		"issuer_url":       "https://auth.example.com",
		"http_listen_addr": "127.0.0.1:8080",
		"secrets": map[string]any{
			"provider":         "env",
			"signing_key_name": "TRUSTER_SIGNING_KEY",
		},
		"user_login_connectors": map[string]any{
			"google": map[string]any{
				"type":               "google",
				"display_name":       "Google",
				"credentials_secret": "TRUSTER_GOOGLE_CREDENTIALS",
			},
		},
		"static_policy": map[string]any{
			"default_redirect_uris": []any{"http://localhost:8000"},
			"clients":               map[string]any{"kubelogin": map[string]any{}},
		},
	}
	addGitHub := func(cfg map[string]any) {
		cfg["user_login_connectors"].(map[string]any)["github"] = map[string]any{
			"type":               "github",
			"display_name":       "GitHub",
			"credentials_secret": "TRUSTER_GITHUB_CREDENTIALS",
		}
	}
	addEmail := func(cfg map[string]any) {
		cfg["user_login_connectors"].(map[string]any)["email"] = map[string]any{
			"type":         "email",
			"display_name": "Email code",
		}
		cfg["email"] = map[string]any{
			"verification_mode": "disabled",
			"otp_secret_name":   "TRUSTER_OTP_SECRET",
			"smtp": map[string]any{
				"host":               "smtp.example.com",
				"port":               json.Number("587"),
				"from_address":       "auth@example.com",
				"credentials_secret": "TRUSTER_SMTP_CREDENTIALS",
			},
		}
	}

	tests := []struct {
		name   string
		valid  bool
		mutate func(map[string]any)
	}{
		{"base configuration", true, func(map[string]any) {}},
		{"complete serving certificate", true, func(cfg map[string]any) {
			cfg["serving_certificate"] = map[string]any{"certificate_file": "/cert/tls.crt", "private_key_file": "/cert/tls.key"}
		}},
		{"empty serving certificate", false, func(cfg map[string]any) { cfg["serving_certificate"] = map[string]any{} }},
		{"serving certificate missing key", false, func(cfg map[string]any) {
			cfg["serving_certificate"] = map[string]any{"certificate_file": "/cert/tls.crt"}
		}},
		{"serving certificate missing certificate", false, func(cfg map[string]any) {
			cfg["serving_certificate"] = map[string]any{"private_key_file": "/cert/tls.key"}
		}},
		{"legacy connectors field", false, func(cfg map[string]any) {
			cfg["connectors"] = cfg["user_login_connectors"]
		}},
		{"legacy root policy field", false, func(cfg map[string]any) {
			cfg["clients"] = cfg["static_policy"].(map[string]any)["clients"]
		}},
		{"legacy OIDC trust field", false, func(cfg map[string]any) {
			cfg["oidc_trust"] = map[string]any{}
		}},
		{"GitHub preset issuer override", false, func(cfg map[string]any) {
			cfg["service_token_issuers"] = map[string]any{"github": map[string]any{"provider": "github", "issuer_url": "https://evil.example.com"}}
		}},
		{"GitHub preset signing algorithms override", false, func(cfg map[string]any) {
			cfg["service_token_issuers"] = map[string]any{"github": map[string]any{"provider": "github", "signing_algs": []any{"RS256"}}}
		}},
		{"Buildkite preset token age override", false, func(cfg map[string]any) {
			cfg["service_token_issuers"] = map[string]any{"buildkite": map[string]any{"provider": "buildkite", "max_token_age": "5m"}}
		}},
		{"complete custom OIDC issuer", true, func(cfg map[string]any) {
			cfg["service_token_issuers"] = map[string]any{"custom": map[string]any{"provider": "oidc", "issuer_url": "https://issuer.example.com", "signing_algs": []any{"RS256"}, "max_token_age": "5m"}}
		}},
		{"mixed connectors require encryption", false, addGitHub},
		{"GitHub with encryption", true, func(cfg map[string]any) {
			addGitHub(cfg)
			cfg["secrets"].(map[string]any)["encryption_key_name"] = "TRUSTER_ENCRYPTION_KEY"
		}},
		{"static refresh requires encryption", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"refresh_tokens": map[string]any{"enabled": true}}
		}},
		{"static refresh with encryption", true, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"refresh_tokens": map[string]any{"enabled": true}}
			cfg["secrets"].(map[string]any)["encryption_key_name"] = "TRUSTER_ENCRYPTION_KEY"
		}},
		{"email-only static refresh without encryption", true, func(cfg map[string]any) {
			addEmail(cfg)
			delete(cfg["user_login_connectors"].(map[string]any), "google")
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"refresh_tokens": map[string]any{"enabled": true}}
		}},
		{"static offline access requires refresh", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"refresh_tokens": map[string]any{"allow_offline_access": true}}
		}},
		{"email connector requires email configuration", false, func(cfg map[string]any) {
			cfg["user_login_connectors"].(map[string]any)["email"] = map[string]any{
				"type":         "email",
				"display_name": "Email code",
			}
		}},
		{"email connector with delivery configuration", true, addEmail},
		{"email delivery without SMTP authentication", true, func(cfg map[string]any) {
			addEmail(cfg)
			delete(cfg["email"].(map[string]any)["smtp"].(map[string]any), "credentials_secret")
		}},
		{"provider verification requires delivery configuration", false, func(cfg map[string]any) {
			cfg["email"] = map[string]any{"verification_mode": "provider"}
		}},
		{"client requires effective redirect URI", false, func(cfg map[string]any) {
			delete(cfg["static_policy"].(map[string]any), "default_redirect_uris")
		}},
		{"client redirect URI can replace defaults", true, func(cfg map[string]any) {
			policy := cfg["static_policy"].(map[string]any)
			delete(policy, "default_redirect_uris")
			policy["clients"].(map[string]any)["kubelogin"] = map[string]any{
				"redirect_uris": []any{"https://app.example.com/callback"},
			}
		}},
		{"required ES512 DPoP and PAR", true, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{
				"dpop":        map[string]any{"mode": "required", "signing_algorithm": "ES512"},
				"require_par": true,
			}
		}},
		{"legacy scalar DPoP", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"dpop": "required"}
		}},
		{"unsupported DPoP algorithm", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"dpop": map[string]any{"mode": "required", "signing_algorithm": "ES384"}}
		}},
		{"algorithm on disabled DPoP", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"dpop": map[string]any{"mode": "disabled", "signing_algorithm": "ES512"}}
		}},
		{"legacy long PAR setting", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["clients"].(map[string]any)["kubelogin"] = map[string]any{"require_pushed_authorization_requests": true}
		}},
		{"external HTTP issuer", false, func(cfg map[string]any) {
			cfg["issuer_url"] = "http://auth.example.com"
		}},
		{"HTTPS homepage", true, func(cfg map[string]any) {
			cfg["homepage_url"] = "https://app.example.com/sign-in"
		}},
		{"external HTTP homepage", false, func(cfg map[string]any) {
			cfg["homepage_url"] = "http://app.example.com"
		}},
		{"unsupported redirect URI scheme", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["default_redirect_uris"] = []any{"ftp://app.example.com/callback"}
		}},
		{"display name is not a bare sender address", false, func(cfg map[string]any) {
			addEmail(cfg)
			cfg["email"].(map[string]any)["smtp"].(map[string]any)["from_address"] = "Truster <auth@example.com>"
		}},
		{"group mapping requires a dotted email domain", false, func(cfg map[string]any) {
			cfg["static_policy"].(map[string]any)["user_group_mappings"] = map[string]any{
				"groups": map[string]any{"alice@localhost": []any{"developers"}},
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance := cloneJSONValue(t, base).(map[string]any)
			test.mutate(instance)
			err := compiledSchema.Validate(instance)
			if (err == nil) != test.valid {
				t.Fatalf("validation error = %v, want valid = %v", err, test.valid)
			}
		})
	}
}

// TestPolicyDatabaseSchemaAndLoaderValidation exercises the policy database configuration schema and authoritative startup validation.
func TestPolicyDatabaseSchemaAndLoaderValidation(t *testing.T) {
	schema := compileConfigSchema(t)
	base := map[string]any{
		"issuer_url": "https://auth.example.com", "http_listen_addr": "127.0.0.1:8080",
		"secrets":               map[string]any{"provider": "env", "signing_key_name": "SIGNING"},
		"user_login_connectors": map[string]any{"google": map[string]any{"type": "google", "display_name": "Google", "credentials_secret": "GOOGLE"}},
		"policy_database": map[string]any{
			"driver": "postgresql", "connection_string_secret": "DATABASE_URL", "redirect_uris": []any{"http://localhost:18000"},
			"queries": map[string]any{"client_exists": "select true as exists", "user_access": "select true as allowed, array[]::text[] as groups", "trust_bindings": "select 1 where false"},
		},
	}
	tests := []struct {
		name        string
		schemaValid bool
		loaderValid bool
		edit        func(map[string]any)
	}{
		{"policy-database-only", true, true, func(map[string]any) {}},
		{"dynamic refresh requires encryption", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_defaults"] = map[string]any{"refresh_tokens": map[string]any{"enabled": true}}
		}},
		{"dynamic refresh with encryption", true, true, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_defaults"] = map[string]any{"refresh_tokens": map[string]any{"enabled": true}}
			c["secrets"].(map[string]any)["encryption_key_name"] = "ENCRYPTION"
		}},
		{"email-only dynamic refresh without encryption", true, true, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_defaults"] = map[string]any{"refresh_tokens": map[string]any{"enabled": true}}
			c["user_login_connectors"] = map[string]any{"email": map[string]any{"type": "email", "display_name": "Email code"}}
			c["email"] = map[string]any{
				"verification_mode": "disabled", "otp_secret_name": "OTP",
				"smtp": map[string]any{"host": "smtp.example.com", "port": json.Number("587"), "from_address": "auth@example.com", "credentials_secret": "SMTP"},
			}
		}},
		{"equivalent Go duration", true, true, func(c map[string]any) { c["policy_database"].(map[string]any)["query_timeout"] = "1000ms" }},
		{"coexists with static client", true, true, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": map[string]any{"static": map[string]any{"redirect_uris": []any{"https://app.example/cb"}}}}
		}},
		{"policy user groups required", true, true, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_defaults"] = map[string]any{"require_user_groups_from_policy": true}
		}},
		{"legacy policy database require groups field", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_defaults"] = map[string]any{"require_groups": true}
		}},
		{"null policy database user group requirement", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_defaults"] = map[string]any{"require_user_groups_from_policy": nil}
		}},
		{"legacy groups overrides field", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"groups_overrides": map[string]any{}}
		}},
		{"legacy client groups override field", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": map[string]any{"static": map[string]any{"redirect_uris": []any{"https://app.example/cb"}, "groups_override": "developers"}}}
		}},
		{"legacy static require groups field", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"require_groups": true}
		}},
		{"legacy client require groups field", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": map[string]any{"static": map[string]any{"redirect_uris": []any{"https://app.example/cb"}, "require_groups": true}}}
		}},
		{"empty static clients", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": map[string]any{}}
		}},
		{"empty static redirect defaults", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"default_redirect_uris": []any{}}
		}},
		{"invalid unused static redirect default", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"default_redirect_uris": []any{"ftp://app.example/callback"}}
		}},
		{"null service token issuers", false, false, func(c map[string]any) {
			c["service_token_issuers"] = nil
		}},
		{"null static policy", false, false, func(c map[string]any) {
			c["static_policy"] = nil
		}},
		{"null static user group requirement", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"require_user_groups_from_policy": nil}
		}},
		{"null static redirect defaults", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"default_redirect_uris": nil}
		}},
		{"null static user group mappings", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"user_group_mappings": nil}
		}},
		{"null static trust policies", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"trust_policies": nil}
		}},
		{"null static clients", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": nil}
		}},
		{"null static client", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": map[string]any{"static": nil}}
		}},
		{"null static client redirects", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"default_redirect_uris": []any{"https://app.example/cb"}, "clients": map[string]any{"static": map[string]any{"redirect_uris": nil}}}
		}},
		{"null static client group requirement", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": map[string]any{"static": map[string]any{"redirect_uris": []any{"https://app.example/cb"}, "require_user_groups_from_policy": nil}}}
		}},
		{"null static refresh setting", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"clients": map[string]any{"static": map[string]any{"redirect_uris": []any{"https://app.example/cb"}, "refresh_tokens": map[string]any{"enabled": nil}}}}
		}},
		{"null user group mapping", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"user_group_mappings": map[string]any{"developers": nil}}
		}},
		{"null user group list", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"user_group_mappings": map[string]any{"developers": map[string]any{"user@example.com": nil}}}
		}},
		{"noncanonical static policy", false, false, func(c map[string]any) {
			c["STATIC_POLICY"] = nil
		}},
		{"noncanonical static client field", false, false, func(c map[string]any) {
			c["static_policy"] = map[string]any{"default_redirect_uris": []any{"https://app.example/cb"}, "clients": map[string]any{"static": map[string]any{"REDIRECT_URIS": nil}}}
		}},
		{"invalid driver", false, false, func(c map[string]any) { c["policy_database"].(map[string]any)["driver"] = "mysql" }},
		{"invalid redirect", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["redirect_uris"] = []any{"http://remote.example/cb"}
		}},
		{"query timeout below boundary", true, false, func(c map[string]any) { c["policy_database"].(map[string]any)["query_timeout"] = "1ms" }},
		{"cache duration above boundary", true, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_lookup_cache"] = map[string]any{"ttl": "2h"}
		}},
		{"invalid duration syntax", false, false, func(c map[string]any) { c["policy_database"].(map[string]any)["query_timeout"] = "soon" }},
		{"invalid cache limit", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["policy_build_cache"] = map[string]any{"max_entries": json.Number("100001")}
		}},
		{"invalid connections", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["max_connections"] = json.Number("33")
		}},
		{"invalid result limit", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["max_json_bytes"] = json.Number("100")
		}},
		{"invalid refresh policy", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["client_defaults"] = map[string]any{"refresh_tokens": map[string]any{"allow_offline_access": true}}
		}},
		{"unknown nested field", false, false, func(c map[string]any) {
			c["policy_database"].(map[string]any)["queries"].(map[string]any)["typo"] = "select 1"
		}},
		{"default queries", true, true, func(c map[string]any) {
			delete(c["policy_database"].(map[string]any), "queries")
		}},
		{"partial query override", true, true, func(c map[string]any) {
			queries := c["policy_database"].(map[string]any)["queries"].(map[string]any)
			delete(queries, "user_access")
			delete(queries, "trust_bindings")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance := cloneJSONValue(t, base).(map[string]any)
			test.edit(instance)
			schemaOK := schema.Validate(instance) == nil
			data, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.jsonc")
			if err = os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, loadErr := Load(path)
			loaderOK := loadErr == nil
			if schemaOK != test.schemaValid || loaderOK != test.loaderValid {
				t.Fatalf("schema valid=%v (want %v), loader valid=%v (want %v): %v", schemaOK, test.schemaValid, loaderOK, test.loaderValid, loadErr)
			}
			if loaded != nil && test.name == "policy-database-only" {
				s := loaded.PolicyDatabase
				if s.QueryTimeout.Duration() != 500*time.Millisecond || s.MaxConnections != 4 || s.ClientLookupCache.MaxEntries != 10000 || s.ClientLookupCache.TTL.Duration() != 5*time.Minute || s.ClientDefaults.RefreshTokens.SessionIdleTTL.Duration() != 30*time.Minute {
					t.Fatalf("unexpected defaults: %#v", s)
				}
			}
			if loaded != nil && test.name == "default queries" {
				queries := loaded.PolicyDatabase.Queries
				if queries.ClientExists != defaultClientExistsQuery || queries.UserAccess != defaultUserAccessQuery || queries.TrustBindings != defaultTrustBindingsQuery {
					t.Fatalf("unexpected query defaults: %#v", queries)
				}
			}
			if loaded != nil && test.name == "partial query override" {
				queries := loaded.PolicyDatabase.Queries
				if queries.ClientExists != "select true as exists" || queries.UserAccess != defaultUserAccessQuery || queries.TrustBindings != defaultTrustBindingsQuery {
					t.Fatalf("unexpected query overrides: %#v", queries)
				}
			}
		})
	}
}

// TestPolicyDatabaseQueryDefaultsMatchSchema keeps the documented JSON Schema defaults synchronized with the loader.
func TestPolicyDatabaseQueryDefaultsMatchSchema(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schema", "v2", "config.schema.json")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var document map[string]any
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	queries := document["$defs"].(map[string]any)["policyDatabase"].(map[string]any)["properties"].(map[string]any)["queries"].(map[string]any)["properties"].(map[string]any)
	for name, expected := range map[string]string{
		"client_exists":  defaultClientExistsQuery,
		"user_access":    defaultUserAccessQuery,
		"trust_bindings": defaultTrustBindingsQuery,
	} {
		if got := queries[name].(map[string]any)["default"]; got != expected {
			t.Errorf("%s schema default = %q, want %q", name, got, expected)
		}
	}
}

// TestStateDatabaseSchemaAndLoaderValidation covers state database defaults and validation.
func TestStateDatabaseSchemaAndLoaderValidation(t *testing.T) {
	schema := compileConfigSchema(t)
	base := map[string]any{
		"issuer_url": "https://auth.example.com", "http_listen_addr": "127.0.0.1:8080",
		"secrets":               map[string]any{"provider": "env", "signing_key_name": "SIGNING"},
		"user_login_connectors": map[string]any{"google": map[string]any{"type": "google", "display_name": "Google", "credentials_secret": "GOOGLE"}},
		"static_policy": map[string]any{
			"default_redirect_uris": []any{"http://localhost:8000"}, "clients": map[string]any{"client": map[string]any{}},
		},
		"state_database": map[string]any{"driver": "postgresql", "connection_string_secret": "STATE_DATABASE_URL"},
	}
	tests := []struct {
		name  string
		valid bool
		edit  func(map[string]any)
	}{
		{"defaults", true, func(map[string]any) {}},
		{"migration secret", true, func(c map[string]any) {
			c["state_database"].(map[string]any)["migrations"] = map[string]any{"connection_string_secret": "STATE_MIGRATION_DATABASE_URL"}
		}},
		{"sqlite", true, func(c map[string]any) {
			c["state_database"] = map[string]any{"driver": "sqlite", "path": "/tmp/truster.db"}
		}},
		{"sqlite defaults", true, func(c map[string]any) { c["state_database"] = map[string]any{} }},
		{"omitted state database", true, func(c map[string]any) { delete(c, "state_database") }},
		{"null state database", false, func(c map[string]any) { c["state_database"] = nil }},
		{"empty driver", false, func(c map[string]any) { c["state_database"] = map[string]any{"driver": ""} }},
		{"unknown driver", false, func(c map[string]any) { c["state_database"].(map[string]any)["driver"] = "mysql" }},
		{"missing secret", false, func(c map[string]any) { delete(c["state_database"].(map[string]any), "connection_string_secret") }},
		{"blank secret", false, func(c map[string]any) { c["state_database"].(map[string]any)["connection_string_secret"] = " " }},
		{"sqlite with PostgreSQL field", false, func(c map[string]any) { c["state_database"].(map[string]any)["driver"] = "sqlite" }},
		{"sqlite with zero PostgreSQL field", false, func(c map[string]any) { c["state_database"] = map[string]any{"max_connections": json.Number("0")} }},
		{"sqlite empty path", false, func(c map[string]any) { c["state_database"] = map[string]any{"path": ""} }},
		{"sqlite null path", false, func(c map[string]any) { c["state_database"] = map[string]any{"path": nil} }},
		{"sqlite blank path", false, func(c map[string]any) { c["state_database"] = map[string]any{"path": " "} }},
		{"PostgreSQL with SQLite path", false, func(c map[string]any) { c["state_database"].(map[string]any)["path"] = "/tmp/truster.db" }},
		{"PostgreSQL with empty SQLite path", false, func(c map[string]any) { c["state_database"].(map[string]any)["path"] = "" }},
		{"zero connections", false, func(c map[string]any) { c["state_database"].(map[string]any)["max_connections"] = json.Number("0") }},
		{"nonpositive connections", false, func(c map[string]any) { c["state_database"].(map[string]any)["max_connections"] = json.Number("-1") }},
		{"zero timeout", false, func(c map[string]any) { c["state_database"].(map[string]any)["query_timeout"] = "0s" }},
		{"nonpositive timeout", false, func(c map[string]any) { c["state_database"].(map[string]any)["query_timeout"] = "-1s" }},
		{"null migrations", false, func(c map[string]any) { c["state_database"].(map[string]any)["migrations"] = nil }},
		{"blank migration secret", false, func(c map[string]any) {
			c["state_database"].(map[string]any)["migrations"] = map[string]any{"connection_string_secret": " "}
		}},
		{"noncanonical field name", false, func(c map[string]any) {
			c["state_database"].(map[string]any)["MAX_CONNECTIONS"] = nil
		}},
		{"unknown field", false, func(c map[string]any) { c["state_database"].(map[string]any)["typo"] = true }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			instance := cloneJSONValue(t, base).(map[string]any)
			tc.edit(instance)
			schemaOK := schema.Validate(instance) == nil
			data, _ := json.Marshal(instance)
			path := filepath.Join(t.TempDir(), "config.jsonc")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if schemaOK != tc.valid || (err == nil) != tc.valid {
				t.Fatalf("schema=%v loader error=%v, want valid=%v", schemaOK, err, tc.valid)
			}
			if tc.name == "defaults" && loaded != nil && (loaded.StateDatabase.MaxConnections != 16 || loaded.StateDatabase.QueryTimeout.Duration() != 5*time.Second) {
				t.Fatalf("unexpected PostgreSQL defaults: %#v", loaded.StateDatabase)
			}
			if (tc.name == "sqlite defaults" || tc.name == "omitted state database") && loaded != nil && (loaded.StateDatabase.Driver != "sqlite" || loaded.StateDatabase.Path != "data/truster-state.db") {
				t.Fatalf("unexpected SQLite defaults: %#v", loaded.StateDatabase)
			}
		})
	}
}

// compileConfigSchema compiles the repository's v2 configuration schema.
func compileConfigSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaPath := filepath.Join("..", "..", "schema", "v2", "config.schema.json")
	schemaFile, err := os.Open(schemaPath)
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := schemaFile.Close(); closeErr != nil {
			t.Errorf("close schema: %v", closeErr)
		}
	})

	schemaDocument, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(configSchemaID, schemaDocument); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	compiledSchema, err := compiler.Compile(configSchemaID)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return compiledSchema
}

// parseJSONCInstance parses a JSONC document into a schema-validation value.
func parseJSONCInstance(t *testing.T, data []byte) any {
	t.Helper()
	standardJSON, err := hujson.Standardize(data)
	if err != nil {
		t.Fatalf("standardize JSONC: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(standardJSON))
	if err != nil {
		t.Fatalf("parse JSONC: %v", err)
	}
	return instance
}

// cloneJSONValue returns an independent JSON-compatible copy of a value.
func cloneJSONValue(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON value: %v", err)
	}
	return parseJSONCInstance(t, data)
}
