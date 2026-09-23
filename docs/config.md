---
draft: false
title: 'Configuration Reference'
linkTitle: 'Configuration'
weight: 7
---

Truster reads a JSONC configuration file. Run it with
`truster serve --config config.jsonc` or set `TRUSTER_CONFIG_PATH`; the
default is `./config.jsonc`.

For OIDC, OAuth, and token terminology used here, see the
[concepts and terminology reference](/docs/concepts/).

Add the versioned JSON Schema to receive editor validation, completion, and
field documentation:

```jsonc
{
  "$schema": "https://truster.dev/schema/v2/config.schema.json",
  // ...
}
```

The schema catches structural errors while editing. `truster check config`
remains authoritative for runtime configuration constraints, while
`truster check templates` validates all effective templates.

See the [example configurations](https://github.com/truster-dev/truster/tree/main/examples/config),
including `config-multiple.jsonc` for multiple connectors, email codes, SMTP, and
Turnstile.

SQLite is the simplest state database for one replica. For PostgreSQL protocol
state shared across replicas, see the [state database guide](state-database.md)
and `config-state-db.jsonc`.

For clients, users, groups, and trust bindings supplied by database policy, see
the [policy database guide](policy-database.md) and `config-policy-db.jsonc`.
Truster only reads this optional PostgreSQL policy database; operators or
another system write its policy data. It is separate from the state database.

## External OIDC trust

External OIDC and CI identities use three configuration layers:

- `service_token_issuers` defines accepted token issuers.
- `static_policy.trust_policies` defines reusable claim requirements.
- Static client `trust_bindings` authorize policies and assign a subject and groups.

```jsonc
{
  "service_token_issuers": {
    "github-actions": { "provider": "github" }
  },
  "static_policy": {
    "trust_policies": {
      "acme-github": {
        "issuer": "github-actions",
        "required_claims": {
          "repository_owner_id": { "const": "123456" }
        }
      }
    },
    "clients": {
      "cluster-production": {
        "redirect_uris": ["http://localhost:8000/callback"],
        "trust_bindings": [{
          "id": "github-production",
          "trust_policy": "acme-github",
          "subject": "trusted:github:acme/app:production",
          "groups": ["podplane:operators"],
          "claims": {
            "repository_id": { "const": "987654" },
            "environment": { "const": "production" },
            "job_workflow_ref": {
              "const": "acme/deploy/.github/workflows/deploy.yml@refs/heads/main"
            }
          }
        }]
      }
    }
  }
}
```

Issuer `provider` is `github`, `buildkite`, or `oidc`. The GitHub and Buildkite
presets supply their official issuer settings and do not accept overrides for
`issuer_url`, `signing_algs`, or `max_token_age`. Generic `oidc` issuers require
all three settings; HTTPS is required except on localhost.

Claim rules are JSON Schema fragments, and every configured claim must be present.
The `claims` from a binding are overlayed on top of `claims` from a policy, where
each `claims` from the binding replaces those with the same name in the policy,
while policy `required_claims` always remain in effect.

Binding `subject` and `groups` replace the corresponding policy values when set.
The effective subject must start with `trusted:`, groups must be non-empty, and
exactly one binding must match a token.

You can check a token against the configured trust policies with:

```sh
truster check trust \
  --config config.jsonc \
  --client-id cluster-production \
  --token-file token.jwt
```

Use `--token-file -` to read from standard input.

In production, prefer immutable organization, repository, and pipeline IDs; constrain
the approved workflow or step; and assign a dedicated least-privilege Kubernetes group.

## Deployment modules

This page is the source of truth for Truster application configuration. The
official OpenTofu/Terraform modules model the application-owned settings as a
typed `truster_config` object and add deployment-owned values such as the
issuer, listen address, state database path, and cloud secrets provider.

- [AWS module inputs](https://github.com/truster-dev/terraform-aws-truster#variables)
- [Google Cloud module inputs](https://github.com/truster-dev/terraform-google-truster#variables)
- [Deployment guides](/docs/deploy/)

Keep infrastructure settings in the module arguments and application settings
under `truster_config`. The modules catch type errors and selected cross-field
errors during planning; Truster remains authoritative for complete runtime
validation.

## Core settings

| Setting | Required | Description |
|---|---:|---|
| `issuer_url` | yes | Public issuer URL. HTTPS is required except on localhost. |
| `homepage_url` | no | URL to redirect to if users visit Truster directly e.g. your app home page. HTTPS is required except on localhost. |
| `http_listen_addr` | yes | Address used by the built-in server. |
| `serving_certificate` | no | Enables native HTTPS using `certificate_file` and `private_key_file`. Both paths are required when set. The files are reloaded in place after certificate rotation; a failed reload retains the last valid certificate. |
| `state_database` | no | Protocol-state database. Defaults to SQLite at `./data/truster-state.db`. |
| `signing_algorithm` | no | Defaults to `RS256`. Supports the asymmetric algorithms advertised by Truster. |
| `jwks_kid` | no | Signing key ID. Derived from the public key when omitted. |
| `access_token_ttl` | no | Access-token lifetime using Go duration syntax; defaults to `15m`. |
| `id_token_ttl` | no | ID-token lifetime using Go duration syntax; defaults to `15m`. |
| `templates_dir` | no | Directory containing template overrides. `TRUSTER_TEMPLATES_DIR` takes precedence. |
| `user_login_connectors` | yes | Interactive user login integrations keyed by connector ID. |
| `service_token_issuers` | no | External issuers accepted for service-token exchange. |
| `static_policy` | conditional | Static clients and authorization policy. Required without `policy_database`. |

`state_database.driver` is `sqlite` (the default) or `postgresql`. SQLite accepts
`path`, is simplest for one replica, and should use an absolute path in production.
PostgreSQL shares protocol state across replicas and accepts
`connection_string_secret`, `max_connections`, `query_timeout`, and a migration-only
secret under `migrations.connection_string_secret`. The state database also holds the
durable single-use PAR, authorization-code, refresh-token, and revocation state. DPoP
replay hashes use a bounded process-local cache instead. See the
[state database guide](state-database.md).

## Native HTTPS

Truster can serve HTTPS directly when a trusted proxy does not terminate TLS
for it. Configure paths to a PEM certificate chain and matching private key:

```jsonc
"serving_certificate": {
  "certificate_file": "/var/run/truster/tls/tls.crt",
  "private_key_file": "/var/run/truster/tls/tls.key"
}
```

Both files must be readable and valid at startup. Truster periodically reloads
the pair, so cert-manager and other atomic file mounts can renew the certificate
without restarting the process. An invalid replacement is logged and the last
valid certificate remains active. When this setting is omitted, the server uses
HTTP and a proxy such as Caddy or an Ingress should terminate TLS.

## Secrets

`secrets.provider` is one of `aws-secrets-manager`, `aws-parameter-store`,
`google-secret-manager`, `azure`, `file`, or `env`. Secret values are
loaded once during startup. With the `env` provider, each configured secret name
is the exact environment variable to read. With `file`, `file_directory` is
required and each secret name is a relative path beneath
that directory. Absolute paths, traversal, and symlinks that escape the directory
are rejected.

```jsonc
"secrets": {
  "provider": "file",
  "file_directory": "/var/run/secrets/truster",
  "signing_key_name": "signing-key.pem",
  "encryption_key_name": "encryption-key"
}
```

The file provider is recommended when an orchestrator can mount values
directly from an external secret manager, such as with the Kubernetes Secrets
Store CSI Driver. Secret files are read once during startup; restart Truster
after rotation. Avoid synchronizing mounted values into Kubernetes Secrets when
the external provider can supply them directly.

`signing_key_name` is always required. `encryption_key_name` is required for GitHub
connectors and whenever a refresh-enabled client can use a non-email connector. Its
value must be a 64-character hex-encoded 32-byte master key:

```console
openssl rand -hex 32
```

Truster derives purpose-specific keys from this master with HKDF-SHA256 and
versioned, domain-separated labels. The signing key and OTP secret remain
separate because they have different purposes and rotation requirements.

Both AWS providers accept `aws_region`; otherwise the standard AWS SDK region
resolution is used. `aws-parameter-store` requests parameter decryption, so it
supports both `String` and KMS-backed `SecureString` parameters. Azure requires
`azure_keyvault_url`. The AWS principal used for Parameter Store needs
`ssm:GetParameter` and, for a customer-managed KMS key, `kms:Decrypt`.

## User login connectors

`user_login_connectors` is keyed by stable, path-safe connector IDs. IDs may
contain letters, digits, `_`, and `-`, are limited to 64 characters, and become
part of the callback URL: `https://auth.example.com/callback/<connector-id>`.

Each connector has:

| Setting | Description |
|---|---|
| `type` | `google`, `github`, `generic`, or `email`. |
| `display_name` | Label shown on the sign-in selector. |
| `order` | Optional display order. |
| `credentials_secret` | OAuth credential secret; required except for `email`. |
| `scopes` | Optional OAuth scopes; provider defaults apply when omitted. |

OAuth credential secrets contain:

```json
{"client_id":"...","client_secret":"..."}
```

The same connector type can be configured more than once, for example to
aggregate several Dex instances. With one non-email connector, Truster redirects
to it automatically. With multiple sign-in methods, it renders a selector.

Google supports `google.hd` for a hosted-domain hint. GitHub supports
`github.hostname` for GitHub Enterprise. Generic connectors require
`authorization_url`, `token_url`, and `userinfo_url`; `subject_field` defaults to
`sub`, `email_field` to `email`, and `email_verified_field` to `email_verified`.

Truster stores an upstream credential by connector ID, stable provider subject,
and normalized email. Google and generic OIDC use the provider's `sub`; GitHub
uses its numeric account ID. The normalized email is exposed downstream as `sub`,
allowing different sign-in methods for the same email to resolve to the same
downstream identity. The `email_verified` claim reflects the accepted provider
assertion or completed local verification.

GitHub users are asked to choose when their account returns multiple email
addresses. The page displays each address's primary and verified status; Truster
does not silently choose one. GitHub-generated `users.noreply` addresses are
excluded because they cannot receive verification codes.

## Email authentication and verification

An `email` connector adds direct sign-in with a typed one-time code. The same
email configuration verifies OAuth identities according to the configured
verification policy.

The `email` configuration is optional. When it is omitted, email verification is
disabled and Truster accepts the provider's chosen email and preserves its
`email_verified` assertion.

```jsonc
"email": {
  "verification_mode": "provider",
  "otp_secret_name": "TRUSTER_OTP_SECRET",
  "otp_ttl": "5m",
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "tls_mode": "starttls",
    "from_name": "Truster",
    "from_address": "auth@example.com",
    "credentials_secret": "TRUSTER_SMTP_CREDENTIALS"
  },
  "turnstile": {
    "site_key": "...",
    "secret_name": "TRUSTER_TURNSTILE_SECRET",
    "remote_ip": {
      "source": "header",
      "header": "CF-Connecting-IP"
    }
  }
}
```

`verification_mode` defaults to `disabled`:

- `disabled` accepts the provider's chosen email without local verification and
  preserves the provider's `email_verified` assertion. SMTP is not required.
- `provider` trusts a current upstream `email_verified` assertion, otherwise it
  requires local verification.
- `strict` ignores the provider assertion and requires local verification once
  for each connector identity and exact email.

`provider` and `strict` require complete OTP and SMTP configuration. A direct
`email` connector also always requires OTP and SMTP, regardless of verification
mode, because the code is its authentication mechanism. In `disabled` mode SMTP
may be omitted; if supplied, it is still validated during startup.

SMTP authentication is optional. When `credentials_secret` is configured, its
secret must contain `{"username":"...","password":"..."}`; when omitted,
Truster does not issue SMTP `AUTH`. `tls_mode` is `starttls` (the default),
`implicit`, or `plaintext`. Plaintext SMTP is only permitted when `host` is
exactly `localhost`, and startup prints a prominent warning because email
addresses, message contents, and one-time codes cross the connection without
encryption.

OTPs are random eight-digit, single-use codes. Their lifetime defaults to five
minutes and must be a whole number of minutes from one to ten. A challenge allows
five attempts, resends have a 60-second cooldown, and sends are limited to five
per normalized email address per rolling hour.

Cloudflare Turnstile is optional, but strongly recommended when direct email
authentication is enabled. Without a challenge provider, attackers can still
cause unwanted email within the per-address rate limit. Future challenge-provider
support is intended to keep this integration vendor-neutral.

`remote_ip` is optional. When omitted, Truster does not send an IP address to
Turnstile. If Truster is directly exposed to customers (not behind a load
balancer for exmaple), use `{"source":"remote_addr"}`. If Turster is behind a
reverse proxy, use `{"source":"header","header":"..."}` only when Truster is
reachable exclusively through a trusted proxy that replaces the named header.
A single address and comma-separated forwarding headers such as
`X-Forwarded-For` are supported; for the latter, Truster uses the first address.
If Truster is deployed behind a Cloudflare Tunnel, use `CF-Connecting-IP`.

## Clients and groups

`static_policy.clients` is a map keyed by downstream OIDC client ID. Each client can set
`redirect_uris`, `user_group_mapping`, and `require_user_groups_from_policy`. When
`redirect_uris` is omitted, `static_policy.default_redirect_uris` is used. Plain HTTP
redirects are accepted only for localhost.

Each client also has a `dpop` object. Its `mode` is `disabled` (the default) or
`required`; `signing_algorithm` is `ES256` by default for required clients and may be
`ES512`. ES256 requires P-256 and ES512 requires P-521. Use separate client IDs rather
than changing an existing client between modes or algorithms. `require_par` defaults to
`false`; when true, authorization parameters must first be posted to `/par` and the
browser sends only `client_id` and the returned one-time `request_uri` to `/authorize`.
The same settings are available under `policy_database.client_defaults` for dynamically
resolved clients.
See [DPoP Integration](/docs/dpop/) for PAR flows, client key lifecycle, BFF design,
resource-server verification, replay storage, and operational requirements.

`static_policy.user_group_mappings` contains named email-to-group maps. A client's
`user_group_mapping` selects one map. Emails are normalized to lowercase before
lookup, and groups are deduplicated before being emitted in the token.
`require_user_groups_from_policy` defaults to `true`; upstream group claims do
not satisfy it.

## Custom templates

Truster embeds defaults in the binary. `templates_dir` overlays that embedded
filesystem: provide only the files you want to replace.

| Path | Data |
|---|---|
| `pages/layout.html` | Common HTML page layout. Receives the current page's data and the shared data described below. |
| `pages/selector.html` | `.Title`, `.Screen` (`login` or `signup`), `.State`, `.SiteKey`, `.Connectors` (`.ID`, `.DisplayName`, `.URL`, `.Email`). |
| `pages/identity.html` | `.Title`, `.Token`, `.Emails` (`.Address`, `.Verified`, `.Primary`). |
| `pages/otp.html` | `.Title`, `.ChallengeID`, `.Message`, `.Error`, `.Email`, `.ExpiresAt`, `.ExpiresIn`, `.RetryAfter`, `.RetryAfterSeconds`. |
| `pages/error.html` | `.Title`, `.Message`. |
| `pages/consent.html` | `.Title`, `.State`, `.ClientID`. |
| `pages/grants.html` | `.Title`, `.Email`, `.Message`, `.Grants` (`.SID`, `.ClientID`, `.Mode`, `.ActionToken`, `.Email`, `.CreatedAt`, `.LastUsedAt`, `.ExpiresAt`). |
| `email/layout.html` | Common HTML email layout. |
| `email/otp.html` | `.Code`, `.ExpiresAt`, `.ExpiresIn`. |
| `email/layout.txt` | Common plain-text email layout. |
| `email/otp.txt` | `.Code`, `.ExpiresAt`, `.ExpiresIn`. |
| `email/otp.subject.txt` | Email subject using `.Code`, `.ExpiresAt`, `.ExpiresIn`. |

Every page and the common page layout can also use `.IssuerURL`,
`.HomepageURL`, and `.Request.Method`, `.Request.Host`, and `.Request.Path`.
Request headers, cookies, query parameters, and form values are intentionally not
exposed because authentication requests can contain sensitive values.

`.ExpiresAt` is an exact UTC `time.Time`; `.ExpiresIn` is the configured
`time.Duration`. On the OTP page, `.RetryAfter` is the remaining resend cooldown
as a `time.Duration`, and `.RetryAfterSeconds` is that duration rounded up to a
whole number of seconds. For example:

```gotemplate
It expires at {{.ExpiresAt.Format "15:04 MST"}}
(in {{printf "%.0f" .ExpiresIn.Minutes}} minutes).
```

Page content templates define `content`; layouts render it with
`{{template "content" .}}`. Email HTML and text templates each have their own
layout. The email subject template defines `subject` and must render a non-empty
single line.

### Static assets

Regular files beneath `public/` are served at root paths. For example,
`public/robots.txt` is available at `/robots.txt` and `public/images/logo.svg`
at `/images/logo.svg`. Existing OIDC routes take precedence. Public files support
`GET` and `HEAD`, use their detected content type, and are served with
`Cache-Control: no-cache`. The `public/` directory and its contents must not be
symlinks. Production loads these files at startup; the development server reloads
them when they change.

### Validate and develop templates

All effective templates are parsed and test-rendered during startup. A parse or
render error prevents the server from starting.

Validate configuration and templates separately in CI with:

```console
truster check config --config ./config.jsonc
truster check templates --config ./config.jsonc
```

Develop overlays with mock data and live reload using:

```console
truster dev --templates-dir ./templates
```

The development server disables Turnstile and opens an index of page and email
previews. Press `o` to open it in a browser.
