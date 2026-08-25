<!--
Truster <https://truster.dev>
Copyright The Truster Authors
SPDX-License-Identifier: Apache-2.0
-->

# Local Development Setup

## Quick Start

Verify tools and install Git hooks:

```bash
make setup
```

Copy `.env.example` to `.env`, then generate a signing key and encryption key:

```bash
cp .env.example .env
scripts/generate-signing-key.sh | pbcopy
openssl rand -hex 32
```

Paste the keys into `TRUSTER_SIGNING_KEY` and `TRUSTER_ENCRYPTION_KEY` in
`.env`. The encryption key is currently used when testing GitHub connectors.

## Configure Google OAuth

1. Create an OAuth 2.0 Client ID in the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Add `http://localhost:8080/callback/google` as an authorized redirect URI. The final path component is the connector ID from the config, not its connector type.
3. Configure the connector's credential secret as one JSON environment variable:

```bash
export TRUSTER_GOOGLE_CREDENTIALS='{"client_id":"123456789.apps.googleusercontent.com","client_secret":"replace-me"}'
```

Each configured OAuth connector has its own `credentials_secret`, so multiple
Google, GitHub, or generic connectors can run simultaneously.

## Build and run

Load `.env` with `direnv` or your preferred shell tooling, then run:

```bash
make build
./bin/truster serve --config examples/config/config-local-dev.jsonc --debug
```

Validate configuration and all effective templates separately without loading
operational secrets or contacting external services:

```bash
./bin/truster check config --config examples/config/config-local-dev.jsonc
./bin/truster check templates --config examples/config/config-local-dev.jsonc
```

Develop custom templates with mock data, no operational secrets, and automatic
reloads:

```bash
make dev
```

Test with kubelogin in another terminal:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=http://localhost:8080 \
  --oidc-client-id=kubelogin-local \
  --oidc-extra-scope=email \
  --oidc-extra-scope=groups
```

## Email OTP development

Use [Mailpit](https://github.com/axllent/mailpit) to capture development email locally.
The development configuration uses Mailpit's plaintext, unauthenticated SMTP
defaults, so no local certificates or credentials are required. Run Mailpit directly with Go:

```bash
go run github.com/axllent/mailpit@latest
```

Alternatively, run its container:

```bash
docker run --rm --name truster-mailpit \
  -p 8025:8025 \
  -p 1025:1025 \
  axllent/mailpit
```

For a self-contained demo, start Truster with generated process-scoped secrets
and a temporary SQLite database, then open Mailpit at <http://localhost:8025>:

```bash
go run ./cmd/truster serve --demo
```

To use the editable email development configuration instead, load `.env` and run:

```bash
./bin/truster serve --config examples/config/config-email-dev.jsonc --debug
```

See [`examples/config/config-multiple.jsonc`](examples/config/config-multiple.jsonc)
for a broader example with multiple connectors, provider email verification,
SMTP, and Turnstile. Direct email login works without Turnstile, as in the local
Mailpit example, but doing so is strongly discouraged outside local development
because it exposes the SMTP sender to abuse.

The `.env` file is ignored by Git and must never be committed.

## PostgreSQL state tests

Run the real PostgreSQL migration, concurrency, timeout, and readiness tests
against the pinned local container (an existing `truster-state-test` container
on port 55435 is reused):

```bash
make test-postgresql
```

The equivalent explicit command is:

```bash
TRUSTER_STATE_TEST_DIRECT_DB_URL='postgresql://truster:truster@127.0.0.1:55435/truster_state?sslmode=disable' \
  go test -v -race ./internal/statedb -run PostgreSQL
```

Run the opt-in representative state-operation benchmarks against the same real
PostgreSQL database (the benchmark resets only `truster_state`):

```bash
TRUSTER_STATE_TEST_DIRECT_DB_URL='postgresql://truster:truster@127.0.0.1:55435/truster_state?sslmode=disable' \
  go test ./internal/statedb -run '^$' -bench '^BenchmarkPostgreSQL' -benchmem
```

## Troubleshooting

### Environment variable is not set

Load the example exports into the current shell before starting Truster:

```bash
source .env
```

Do not use `export $(cat .env | xargs)`: it does not safely preserve multiline
PEM signing keys.

### Unknown client ID

The `--oidc-client-id` passed to kubelogin must exactly match a key under
`static_policy.clients` in the selected configuration. The local examples use
`kubelogin-local`.

### OAuth redirect URI mismatch

The upstream OAuth application callback must match the issuer and connector ID
exactly. For the Google local-development connector it is:

```text
http://localhost:8080/callback/google
```

The final path component is the connector ID, not the connector type or display
name.

### Authentication fails because groups are missing

`config-local-dev.jsonc` requires groups. Replace `your-email@example.com` in
`static_policy.user_group_mappings` with the normalized email returned by your
provider, or set `static_policy.require_user_groups_from_policy` to `false` while testing.

### Mailpit authentication fails

- The demo and `config-email-dev.jsonc` use Mailpit's unauthenticated defaults.
  When testing another configuration with `credentials_secret`, configure
  matching Mailpit authentication and allow insecure authentication only for
  local plaintext SMTP.
- If ports `1025` or `8025` are already occupied, stop the existing service or
  consistently change both the Docker port mapping and Truster configuration.

See the main [troubleshooting guide](docs/troubleshooting.md) for deployment,
OIDC, kubelogin, and Kubernetes issues.
