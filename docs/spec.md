---
draft: false
title: 'Truster System Design & Specification'
linkTitle: 'Specification'
weight: 2
---

Truster is a minimal OIDC provider designed primarily for Kubernetes. It
federates authentication to one or more upstream providers, normalizes users to
email identities, and maps those emails to static groups.

See [Concepts and terminology](/docs/concepts/) for the protocol terminology used in
this specification.

## Design goals

- Authorization Code flow with mandatory PKCE S256 for downstream public clients.
- No downstream client secrets.
- Multiple Google, GitHub, generic OAuth2/OIDC, and direct-email connectors.
- Static email-to-group policy with per-client selection.
- A single binary with embedded templates and a SQLite or PostgreSQL state
  database.
- Secrets loaded once at startup from AWS Secrets Manager, AWS Systems Manager
  Parameter Store, Google Secret Manager, Azure Key Vault, or environment
  variables.
- Secure startup validation: invalid configuration, secrets, or templates prevent
  the server from serving requests.

Truster does not provide local passwords, an administration UI, dynamic
upstream-group synchronization, SAML, or non-PKCE downstream flows.

The optional [policy database](policy-database.md) supplies database policy
through bounded, read-only PostgreSQL queries, while static policy retains
precedence for clients with the same ID. Operators or another system write this
policy data; Truster only reads it. The policy database and protocol state
database are separate stores with separate responsibilities.

## Architecture

```text
┌──────────┐  Auth Code + PKCE  ┌───────────────┐   HTTP   ┌───────────┐
│kubelogin │───────────────────▶│ TLS proxy     │─────────▶│ truster │
└──────────┘                    │ (for example, │          └────┬──────┘
                                │ Caddy)        │               │
                                └───────────────┘               ├────▶ State DB
                                                                ├────▶ Optional policy DB
                                                                ├────▶ Secrets provider
                                                                ├────▶ SMTP and Turnstile
                                                                │
                                         ┌──────────┬───────────┼──────────┐
                                         │          │           │          │
                                     ┌───▼────┐ ┌───▼────┐ ┌────▼───┐ ┌────▼───┐
                                     │Google  │ │GitHub  │ │Generic │ │Direct  │
                                     │OAuth   │ │OAuth   │ │OAuth   │ │email   │
                                     └────────┘ └────────┘ └────────┘ └────────┘
```

A TLS reverse proxy normally fronts the server; native HTTPS can instead use a
configured serving certificate. The state database stores
browser authorization state, single-use authorization codes, OTP challenges,
and local email-verification records. SQLite is the simplest choice for one
replica; PostgreSQL shares this protocol state across replicas. It does not
store browser sessions or cookies. The optional PostgreSQL policy database is a
separate, read-only input containing clients, users, groups, and trust policy.
Secrets are loaded once during startup through the configured provider; secret
provider values are not written into the application configuration or either database.

## Authentication flow

1. A downstream client starts `/authorize` with a PKCE challenge.
2. With one OAuth connector, Truster redirects automatically. Otherwise the
   user selects an upstream provider or enters an email address.
3. OAuth connectors return a stable provider subject and one or more email
   assertions. Direct email authentication uses the normalized email as its
   connector subject.
4. If several email assertions are available, the user chooses one from a
   stateless authenticated selection token.
5. Truster accepts the chosen email directly, accepts the provider's
   verification assertion, or requires a typed OTP according to the configured
   verification mode.
6. The original OAuth state is atomically consumed and a single-use opaque
   authorization code is issued.
7. `/token` validates the code and PKCE verifier, resolves current policy groups, and
   returns a signed token.

## Identity model

An upstream credential is identified by connector ID, provider subject, and
normalized email. Connector IDs make repeated instances of the same provider
independent. Google and generic OIDC use `sub`; GitHub uses its numeric account
ID.

Provider subjects are never exposed downstream. The normalized email is used for
downstream `sub` and `email`, so the same email has the same downstream identity
across connectors.

Local verification is recorded for each connector identity and exact email. In
`disabled` mode, the default, Truster accepts the chosen email and preserves the
provider's `email_verified` assertion. In `provider` mode, a current verified
assertion is accepted and an unverified assertion requires local verification.
In `strict` mode, provider assertions are ignored and local verification is
required once.

## Security properties

- PKCE S256 is mandatory for every downstream client.
- Authorization codes and browser state are opaque, single-use, expiring values.
- Identity-selection data is encrypted and authenticated with AES-256-GCM.
- Purpose-specific encryption keys are derived from a master key using
  HKDF-SHA256 with versioned domain separation.
- OTPs are random, single-use, short-lived, attempt-limited, and rate-limited per
  normalized email address.
- SMTP uses TLS by default and supports optional authentication; plaintext mode
  is restricted to `localhost` and emits a prominent startup warning.
- Turnstile can protect direct email initiation; it is optional but recommended.
- Signing keys, encryption keys, OAuth credentials, SMTP credentials, OTP
  secrets, and challenge secrets remain server-side.

## OIDC endpoints

| Endpoint | Purpose |
|---|---|
| `/.well-known/openid-configuration` | Discovery document |
| `/authorize` | Begin authorization and select a sign-in method |
| `/par` | Store a pushed authorization request |
| `/token` | Consume an authorization code and validate PKCE |
| `/revoke` | Revoke a refresh grant |
| `/jwks` | Public signing keys |
| `/userinfo` | Return claims for a valid Truster token |
| `/healthz` | Health check |

Connector callbacks and browser form endpoints are internal parts of the login
flow rather than downstream OAuth APIs.

Truster supports the OIDC `prompt` values `none`, `login`, and `create` and
advertises them through discovery. `create` starts the same authentication flow
with account-creation presentation; it does not guarantee that a new identity
is created. Because Truster has no browser session, `none` returns
`login_required`. Unsupported or combined values are rejected.

## Token identity and groups

Issued tokens include `iss`, `aud`, `sub`, `email`, `email_verified`,
`preferred_username`, `groups`, `iat`, and `exp`. `sub` and `email` contain the
same normalized email. Static groups are selected by downstream client and
resolved at code exchange time.

## Configuration and operations

Configuration is JSONC; see the [Configuration Reference](/docs/config/).
Templates are embedded and may be partially overlaid from a directory. All
configuration and templates are validated before startup. Secrets are fetched
once at startup rather than on each request.

A representative multiple-connector configuration is:

```jsonc
{
  "issuer_url": "https://auth.example.com",
  "http_listen_addr": "127.0.0.1:8080",
  "signing_algorithm": "RS256",

  "secrets": {
    "provider": "env",
    "signing_key_name": "TRUSTER_SIGNING_KEY"
  },

  "state_database": {
    "driver": "sqlite",
    "path": "/var/lib/truster/truster-state.db"
  },

  "user_login_connectors": {
    "company-google": {
      "type": "google",
      "display_name": "Company Google",
      "order": 10,
      "credentials_secret": "TRUSTER_GOOGLE_CREDENTIALS",
      "google": {
        "hd": "example.com"
      }
    },
    "engineering-dex": {
      "type": "generic",
      "display_name": "Engineering Dex",
      "order": 20,
      "credentials_secret": "TRUSTER_DEX_CREDENTIALS",
      "generic": {
        "authorization_url": "https://dex.example.com/auth",
        "token_url": "https://dex.example.com/token",
        "userinfo_url": "https://dex.example.com/userinfo",
        "subject_field": "sub"
      }
    }
  },

  "static_policy": {
    "default_redirect_uris": ["http://localhost:8000"],
    "user_group_mappings": {
      "production": {
        "alice@example.com": ["cluster-admins", "developers"],
        "bob@example.com": ["developers"]
      }
    },
    "clients": {
      "kubelogin-prod": {
        "user_group_mapping": "production"
      }
    }
  }
}
```

With the `env` provider, the signing key and each OAuth credential name are
environment-variable names. OAuth credential values are JSON objects containing
`client_id` and `client_secret`. Production deployments can instead use AWS
Secrets Manager, AWS Systems Manager Parameter Store, Google Secret Manager, or
Azure Key Vault. See the [example configurations](https://github.com/truster-dev/truster/tree/main/examples/config)
for direct email, GitHub, SMTP, Turnstile, and template settings.

### Group resolution

For an authenticated email and downstream client:

1. Normalize the email to lowercase.
2. Read the client's `user_group_mapping` name.
3. Look up that named map under `static_policy.user_group_mappings`, then look up the email.
4. Return an empty list if either lookup is absent.
5. Deduplicate and sort the resulting groups.
6. Reject token exchange when the effective `require_user_groups_from_policy` setting is true and
   the result is empty.

The client-level `require_user_groups_from_policy` setting overrides
`static_policy.require_user_groups_from_policy`. It defaults to true when neither is configured.
Only groups resolved by Truster policy satisfy this requirement; upstream
group claims do not.

## ID token claims

An issued ID token has claims equivalent to:

```json
{
  "iss": "https://auth.example.com",
  "aud": "kubelogin-prod",
  "sub": "alice@example.com",
  "email": "alice@example.com",
  "email_verified": true,
  "preferred_username": "alice",
  "groups": ["cluster-admins", "developers"],
  "iat": 1753650000,
  "exp": 1753650900,
  "nonce": "optional-client-nonce"
}
```

| Claim | Meaning |
|---|---|
| `iss` | Configured Truster issuer URL. |
| `aud` | Downstream client ID that initiated authorization. |
| `sub` | Normalized email; provider subjects are never exposed. |
| `email` | The same normalized email identity used downstream. |
| `email_verified` | Provider assertion in disabled mode; true after accepted provider or local verification in provider/strict modes. |
| `preferred_username` | Local part of the email address. |
| `groups` | Sorted static groups resolved for the downstream client. |
| `iat`, `exp` | Issue and expiry times; lifetimes are controlled independently by `access_token_ttl` and `id_token_ttl`. |
| `nonce` | Included only when supplied in the authorization request. |

### PKCE enforcement

- `/authorize` requires `code_challenge` and `code_challenge_method=S256`.
- `/token` requires the matching `code_verifier`.
- Authorization codes are opaque, expiring, atomically consumed, and cannot be
  exchanged twice.
- There is no fallback to a non-PKCE flow and downstream client secrets are not
  supported.

## Kubernetes integration

Kubernetes API servers can validate Truster tokens directly:

```text
--oidc-issuer-url=https://auth.example.com
--oidc-client-id=kubelogin-prod
--oidc-username-claim=email
--oidc-groups-claim=groups
```

Users can configure [kubelogin](https://github.com/int128/kubelogin) as a
kubeconfig exec credential plugin:

```yaml
users:
- name: oidc-prod
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kubelogin
      args:
      - get-token
      - --oidc-issuer-url=https://auth.example.com
      - --oidc-client-id=kubelogin-prod
      - --oidc-pkce-method=S256
```

Kubernetes uses `email` as the RBAC username and `groups` for group bindings. See
the [Kubernetes integration guide](/docs/kubernetes/) for cluster-specific setup,
RBAC examples, and complete kubeconfig instructions.

## OpenTofu/Terraform deployment

The companion modules provision the cloud runtime around the binary:

- `terraform-aws-truster` provisions an ARM64 or AMD64 EC2 instance, IAM
  permissions, security groups, optional networking resources, systemd services,
  and Caddy.
- `terraform-google-truster` provisions a Compute Engine VM, service account,
  firewall rules, optional networking resources, systemd services, and Caddy.

The module names retain `terraform` for registry and repository compatibility,
but examples use the OpenTofu CLI:

```console
tofu init
tofu plan
tofu apply
```

Secrets should be created outside OpenTofu/Terraform and passed to the module by
name or ARN so secret values do not enter state. Instance startup writes the
JSONC configuration, starts Truster and Caddy, and lets Truster read its
configured secrets using the instance IAM role or service account. See the
[AWS deployment guide](/docs/deploy/aws/) for the complete module example,
variables, outputs, DNS, and replacement procedure, or the
[Google Cloud module](https://github.com/truster-dev/terraform-google-truster/blob/main/README.md#usage)
for Google Cloud deployment instructions.

## Implementation dependencies

The main direct dependencies and their responsibilities are:

| Dependency | Purpose |
|---|---|
| `github.com/lestrrat-go/jwx/v2` | JWT signing and verification; JWK and JWKS handling. |
| `golang.org/x/oauth2` | Upstream OAuth 2.0 authorization and token exchange. |
| `github.com/tailscale/hujson` | JSONC parsing and standardization. |
| `github.com/spf13/cobra` | Command-line interface. |
| `github.com/mattn/go-sqlite3` | Persistent OAuth state, codes, OTP challenges, and verification records. |
| `github.com/jackc/pgx/v5` | Shared PostgreSQL state and read-only policy queries. |
| AWS SDK for Go v2 | AWS Secrets Manager and Systems Manager Parameter Store. |
| Google Cloud Secret Manager client | Google Secret Manager access. |
| Azure SDK for Go | Azure Key Vault access. |

Signing uses Go's cryptographic implementations through JWX. Supported
algorithms are RS256/384/512, PS256/384/512, ES256/384/512, and EdDSA; RS256 is
the default for broad Kubernetes compatibility.

## Persistence and lifecycle

By default, SQLite state lives at `./data/truster-state.db`; configure
`state_database.path` to move it. SQLite is simplest for one replica.
PostgreSQL shares protocol state across replicas.
Authorization state, codes, OTP challenges, and
verification records survive process restarts. Signing-key rotation currently
requires replacing the configured key and restarting Truster.

Configuration, secrets, and templates are loaded at startup. The process exits
instead of serving requests if configuration validation, secret loading,
template parsing, or template test rendering fails. `truster check config` and
`truster check templates` perform the corresponding checks for CI, while
`truster dev` serves live-reloading template previews with mock data.
