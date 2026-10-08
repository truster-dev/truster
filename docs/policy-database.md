---
draft: false
title: 'Policy Database'
linkTitle: 'Policy Database'
weight: 8
---

A policy database lets Truster use PostgreSQL to decide which clients and
users may sign in, which groups users receive, and which external OIDC
identities may exchange tokens.

This is useful when clients and access rules already belong to an application
database, or when they need to change without restarting Truster. Static
clients remain available and always take precedence over clients supplied by
database policy with the same ID.

Truster only reads the policy database. Operators or another system create and
update its clients, users, groups, and trust bindings.

> **Note:** The policy database does not store or verify user passwords or
> identity provider credentials in PostgreSQL. Users still authenticate through
> Truster's configured identity flows. The policy database only supplies
> client definitions, access decisions, groups, and trust bindings.

The policy database is read-only to Truster; it is not Truster's operational
storage and Truster never writes policy changes to it.
Browser and email-verification state, authorization codes, refresh grants, and
encrypted renewable provider credentials remain in Truster's protocol state
database (SQLite by default, or configured PostgreSQL). Signing keys,
connector secrets, and the PostgreSQL connection string remain in the configured
secrets provider. The connection string is loaded at startup, so rotating it
requires restarting Truster.

The state and policy databases are independently configured, separate stores,
even when both use the same PostgreSQL server. Do not point policy queries at
the state schema or use the policy database for protocol state.

## Quick start

### 1. Create the tables

Truster includes a ready-to-use PostgreSQL schema. Apply it to the database:

```console
psql "$DATABASE_URL" -f examples/policy-db/postgresql.sql
```

The script creates four tables under the `truster_policy` schema:

- `clients` contains client IDs accepted by Truster.
- `users` associates an email subject and groups with a client.
- `trust_issuers` contains OIDC issuers approved for a client.
- `trust_bindings` maps external OIDC identities to subjects and groups.

See [`examples/policy-db/postgresql.sql`](https://github.com/truster-dev/truster/blob/main/examples/policy-db/postgresql.sql)
for the complete definitions.

### 2. Create a read-only login

Truster only needs to read these tables. Create a dedicated login after
replacing the database name and password:

```sql
CREATE ROLE truster_policy LOGIN PASSWORD 'managed-outside-SQL';
GRANT CONNECT ON DATABASE application TO truster_policy;
GRANT USAGE ON SCHEMA truster_policy TO truster_policy;
GRANT SELECT ON ALL TABLES IN SCHEMA truster_policy TO truster_policy;
```

These privileges are the read-only boundary: do not grant this role schema
creation or table write privileges. Apply equivalent restrictions to any
objects referenced by custom queries.

### 3. Configure Truster

Store the PostgreSQL connection string in your configured secrets provider. The
value of `connection_string_secret` is the name of that secret.

All four built-in queries use the tables created above, so the configuration
does not need to contain SQL:

```jsonc
"policy_database": {
  "driver": "postgresql",
  "connection_string_secret": "TRUSTER_POLICY_DB_URL",
  "redirect_uris": ["http://localhost:8000/callback"],
}
```

All clients supplied by database policy use the configured `redirect_uris` and
`client_defaults`.
See [`config-policy-db.jsonc`](https://github.com/truster-dev/truster/blob/main/examples/config/config-policy-db.jsonc)
for a complete example.

### 4. Add a client and user

Email subjects must be lowercase. This example allows `demo@example.com` to use
the `kubelogin` client and assigns the `developers` group:

```sql
INSERT INTO truster_policy.clients (client_id) VALUES ('kubelogin');
INSERT INTO truster_policy.users (client_id, subject, groups)
VALUES ('kubelogin', 'demo@example.com', ARRAY['developers']);
```

## Query contracts

You can use the built-in schema without configuring any queries. To use tables
from an existing application database, override one or more entries under
`policy_database.queries`. Any omitted query continues to use its built-in value.

For a database created with Truster v2, add the `trust_issuers` table from the
current example schema, supply a custom `trust_issuer` query, or set
`trust_issuer` to `null` if you do not need database-managed issuers. Truster v3
prepares all enabled queries at startup, including their built-in defaults.

Set an individual query to `null` to disable that lookup. Empty or whitespace-only
SQL is invalid. Disabling a lookup denies the operation that needs it; it does
not bypass authorization:

| Query set to `null` | Effect |
| --- | --- |
| `client_exists` | Database-managed clients are denied. |
| `user_access` | Human sign-in and refresh for database-managed clients are denied, even when groups are optional. |
| `trust_issuer` | Dynamic issuer lookup is disabled; statically configured issuers remain usable. |
| `trust_bindings` | Service-token exchange for database-managed clients is denied, including when the issuer is statically configured. |

For example, to use database-managed clients and users but only statically
configured service-token issuers:

```jsonc
"queries": {
  "trust_issuer": null
}
```

Truster prepares only enabled queries at startup. These queries are used only
when `policy_database` is configured, and never for static clients. Disabling
all four queries does not affect static-client authorization.

Configured SQL is trusted configuration. Truster binds the values described
below as positional parameters; it never interpolates them into the SQL.

### `client_exists`

Checks whether a client is managed by the policy database.

- Parameters:
  - `$1` — client ID as `text`.
- Result:
  - Exactly one row.
  - `exists` — a non-null `boolean`.

Return `false` for an unknown or disabled client. Returning no row, more than one
row, `NULL`, or another type is treated as a policy database failure rather than
a normal denial.

### `user_access`

Checks whether a user may use a client and returns the user's current groups.

- Parameters:
  - `$1` — client ID as `text`.
  - `$2` — lowercase email subject as `text`.
- Result:
  - Exactly one row, including when the client or user is unknown.
  - `allowed` — a non-null `boolean`.
  - `groups` — a non-null `text[]`.

Return `allowed = false` and an empty group array for an unknown or disabled
client, or for an unknown or disabled user. If groups are required for the
client, an allowed result with an empty group array is denied. Returned groups
must be non-empty strings; Truster deduplicates and sorts them before issuing
a token.

### `trust_issuer`

Resolves an approved OIDC issuer for a database-managed client. Before any
policy database or issuer HTTP request, Truster rejects malformed or oversized
tokens, missing required claims, expired or not-yet-valid tokens, invalid
audiences or authorized parties, and claims exceeding structural safety limits.

Those checks are rejection-only: the token is still unverified. Truster uses its
`iss` value only as an exact lookup key into approved database policy. A matching
row supplies verification settings, not proof of identity. Truster must still
complete OIDC discovery, verify the signature over the original token, repeat
standard-claim validation, enforce the issuer's maximum token age, and match
exactly one trust binding.

The built-in query reads `truster_policy.trust_issuers`. Omit this query to use
that default, or set it to `null` to disable dynamic issuer lookup without
affecting statically configured issuers.

- Parameters:
  - `$1` — client ID as `text`.
  - `$2` — the token's exact `iss` value as `text`.
- Result:
  - Zero or one row. Zero rows deny the issuer.
  - Columns must appear in this order:
    - `issuer_id text`
    - `provider text`, currently exactly `oidc`
    - `issuer_url text`, exactly matching `$2`
    - `signing_algs text[]`
    - `max_token_age_seconds bigint`

The issuer ID must satisfy Truster's trust identifier rules and must not collide
with an ID in `service_token_issuers`. The issuer URL must use HTTPS, signing
algorithms must be supported asymmetric algorithms, and the maximum token age
must be positive. More than one row, malformed values, or a URL that differs
from the lookup value is treated as a policy database failure.

Static `service_token_issuers` take precedence over this query. Truster only
uses `trust_issuer` for database-managed clients and never lets a static client
fall through to database issuer policy.

### `trust_bindings`

Returns the current trust bindings used to evaluate a verified external OIDC
token.

- Parameters:
  - `$1` — client ID as `text`.
  - `$2` — the resolved static or dynamic issuer ID as `text`.
- Result:
  - Zero or more rows.
  - Columns must appear in this order:
    - `client_id text`
    - `issuer_id text`
    - `binding_id text`
    - `subject text`
    - `required_claims json` or `jsonb`
    - `policy_claims json` or `jsonb`
    - `binding_claims json` or `jsonb`
    - `groups text[]`

The returned client and issuer IDs must match the query parameters. Binding IDs
must be unique, start with a letter or digit, and otherwise use only letters,
digits, `_`, `-`, `.`, or `:`, with a maximum length of 64 characters. Subjects
must start with `trusted:` and be no longer than 256 bytes. Groups must be
non-empty, and all three claims columns must contain JSON objects. Claim names
must also be valid for the configured issuer provider.

Binding claims replace policy claims with the same name. Required claims always
apply. A token is accepted only when exactly one compiled binding matches it;
zero or multiple matches are denied.

Custom queries should return bindings only while the client is active. This is
important because Truster rechecks the trust rows after its client-existence
check. The built-in schema enforces this through the foreign key from
`trust_bindings` to `clients` with cascading deletion.

## Clients from static or database policy

Truster resolves each client from either static configuration or the policy
database. If both sources contain the same client ID, static policy wins.

- A static client does not cause any policy database queries.
- Static policy never falls through to database policy, including after a
  denial.
- Clients supplied by database policy share `policy_database.redirect_uris` and
  `policy_database.client_defaults`.
- Client IDs supplied by database policy must be non-empty and no longer than
  256 bytes.
- Users resolved through database policy do not require an external OIDC trust
  issuer.
- Trust bindings loaded from database policy may use a static issuer from
  `service_token_issuers` or the dynamic issuer resolved for the current token.

## Policy database security

Use a dedicated login and pool for Truster, even when another feature uses the
same PostgreSQL server. The dedicated login limits the impact of a mistake in a
query or configuration.

Database-managed issuers must use HTTPS. Truster resolves and connects to them
directly without an HTTP proxy. Before dialing, it rejects loopback, private,
link-local, multicast, unspecified, and shared IPv4 (`100.64.0.0/10`) addresses.
It dials the checked IP rather than resolving the hostname again, and rejects
cross-origin redirects. These checks apply to both discovery and JWKS requests.

Truster does not maintain an exhaustive special-purpose address blocklist or
restrict IPv6 to a particular allocation. Public NAT64 and 6to4 destinations
are not excluded simply because they use translation or tunneling. An address
passing these checks is not proof that its destination is safe: routing or
translation can still lead to private infrastructure, including metadata services.

Use enforced network-egress rules or an egress gateway to restrict the actual
destinations and ports reachable by dynamic issuer requests. Those controls must
cover IPv4, IPv6, and translated traffic. An ambient `HTTPS_PROXY` setting does
not enforce this boundary because dynamic issuer requests bypass it. Take care
not to expose private database, secret-store, or static-issuer destinations to
dynamic issuer requests just because the Truster process needs access to them.

An operator who intentionally needs a private-network issuer must configure it
statically under `service_token_issuers` instead of returning it from database
policy.

For remote connections, use strict TLS:

- Prefer `sslmode=verify-full` when the server certificate and hostname can be
  verified.
- `sslmode=verify-ca` verifies the certificate authority but not the hostname.
- `sslmode=require` encrypts the connection but does not normally authenticate
  the PostgreSQL server.
- For remote targets, modes such as `allow` and `prefer` are rejected because
  they permit plaintext fallback.
- Every parsed primary and fallback target is checked. Plaintext connections are
  only accepted for `localhost` or a loopback IP during development.

At startup, Truster loads the connection secret, checks connectivity, and
prepares each enabled query within a 10-second initialization deadline.
Preparation validates SQL parsing and parameter inference, but does not execute
the statements or verify result aliases, column order, PostgreSQL types,
cardinality, or configured result limits. Those contracts are enforced every
time a query runs. Startup fails if connectivity or preparation fails.

## Limits and caches

For clients supplied by database policy,
`client_defaults.require_user_groups_from_policy` defaults to `true`; static
policy defaults do not apply. Refresh tokens are disabled by default. A
database-authorized user with no groups is therefore denied unless group
requirements are explicitly disabled.

Truster limits query time, connection use, and result sizes. The settings,
defaults, and accepted ranges are:

- `query_timeout`: `500ms` (`10ms` through `30s`) for each query.
- `max_connections`: `4` (`1` through `32`).
- `max_trust_rows`: `100` (`1` through `1000`) rows per trust query.
- `max_groups`: `100` (`1` through `1000`) returned elements in each group
  array, before deduplication.
- `max_group_bytes`: `256` (`1` through `4096`) bytes per non-empty group.
- `max_json_bytes`: `65536` (`1024` through `1048576`) aggregate encoded claim
  JSON bytes across all rows in one trust query.
- `client_lookup_cache.ttl`: `5m`; `negative_ttl`: `30s`. Both may be at most
  `1h`.
- `client_lookup_cache.max_entries` and `policy_build_cache.max_entries`:
  `10000` (`1` through `100000`).

Each policy database query is cancelled if it does not finish within
`query_timeout`. A timeout is treated as a policy database failure, not a
denial: Truster fails closed without using stale user or trust data, while
preserving retryable authorization codes and refresh grants as described below.

Policy queries are compatible with transaction-mode PgBouncer and do not rely
on session-bound prepared statements. Because transaction pooling may route
successive queries to different PostgreSQL sessions, custom queries must use
schema-qualified table names and cannot rely on `search_path`, `SET`, temporary
tables, or other session state. They must run under a role limited to the
required `SELECT` privileges. A replica PgBouncer is suitable only when replica
lag is acceptable for policy changes; use the primary when revocations must take
effect immediately.

The example schema does not enforce every runtime size limit. Invalid rows may
therefore be inserted, but Truster fails closed when it reads them.

Client existence results are cached because they are checked frequently. The
`client_lookup_cache` has separate lifetimes for positive and negative results
and a bounded number of entries. Initial authorization and `/userinfo` may use
this cache. Callback completion, authorization-code redemption, refresh, and
token exchange bypass it.

Dynamic issuer, user-group, and trust-binding rows are never cached. Changes to
those rows are therefore read on the next relevant operation. OIDC discovery
metadata and keys have a separate network cache limited to 1,024 entries with a
five-minute lifetime. Static and dynamic issuers use separate cache entries so
database policy cannot reuse keys fetched through the unrestricted static
transport. A removed or disabled dynamic issuer is denied before that cache is
used. The `policy_build_cache` stores only immutable compiled JSON Schema artifacts.
Changing required, policy, or binding claim-schema content creates a different
cache entry. Subject-only and group-only edits may reuse the compiled schema,
but the current subject and groups are still read from PostgreSQL and applied
immediately.

The defaults are conservative safety ceilings rather than throughput targets.
The authpolicy benchmarks exercise cached client lookup, group normalization,
trust-row processing, and unchanged and changed schema compilation, including
the default maximum group and trust-row counts. Run them with:

```console
go test ./internal/authpolicy -run '^$' -bench . -benchmem
```

Database and network latency vary by deployment. Validate `query_timeout` and
`max_connections` against the production PostgreSQL topology before changing
their defaults.

## When changes take effect

Truster rechecks database policy before issuing or refreshing credentials:

- Interactive login checks the client before redirecting to a provider, checks
  the client and user before creating a code, and checks them again when the code
  is redeemed.
- Refresh checks the client and user on every token rotation.
- Token exchange rejects obviously invalid tokens first, checks the client,
  resolves any dynamic issuer, verifies the external token and its claims,
  and then loads the current trust bindings.

As a result, an existing authorization code or refresh token does not preserve
old client, user-group, or trust policy. The positive client cache reduces
policy database load while a flow is being prepared, but Truster bypasses it
before issuing or refreshing credentials.

These checks affect future authorization and token issuance. They do not revoke
or modify access or ID tokens that have already been issued. Existing JWTs keep
their issued groups and trust-derived subject until they expire. `/userinfo`
returns the claims stored in the access token and rechecks only client existence
through the normal client cache; it does not rerun `user_access`.

PostgreSQL replicas are supported, but replica lag delays every policy database
change. For example, a removed group remains usable until the replica receives
that update for a new decision. Already-issued token lifetime is a separate
lower bound on effective group or trust revocation. Use the primary, synchronous
replication, or an enforced lag limit when rapid revocation matters.

## Denials and policy database failures

Truster distinguishes a normal denial from a failure to obtain a trustworthy
answer.

A **denial** means the query ran successfully and returned a valid negative
answer. Examples include:

- A client or user does not exist.
- A user is not allowed.
- Required groups are empty.
- No trust binding matches, or more than one binding matches.

A **policy database failure** means Truster could not safely decide. Examples
include:

- A timeout, cancelled query, or connection error.
- The wrong number of rows or columns.
- A `NULL` value or unexpected PostgreSQL type.
- Invalid trust policy JSON.
- A configured result limit was exceeded.

Policy database failures fail closed: Truster does not issue a token and does
not use stale user or trust data. A denial or temporary policy database failure
during authorization-code redemption leaves the code unconsumed, so it can be
retried before expiry if policy or availability changes. During refresh, a
definitive client, user, or refresh-policy denial revokes the refresh-token
family. A temporary policy database failure preserves the grant for retry.

## Monitoring

Truster emits structured `policy database query` log events. They include:

- Query name and duration
- Observed row count and resolver outcome (`allowed`, `denied`, or
  `indeterminate`)
- Client ID and issuer ID, where applicable
- Client-cache outcome

These events do not include SQL text, error details, connection strings,
credentials, raw tokens, or user and trust-row subjects. The query outcome
classifies database policy resolution, not necessarily the final token-exchange
decision. For example, a valid zero-row trust query is followed by a denied
`trust exchange` event.

Successful `trust exchange` events include the resolved binding subject and may
include bounded provider identifiers such as run, build, or job IDs. Treat those
fields as potentially sensitive.

Useful conditions to alert on include repeated policy database failures, query
latency approaching `query_timeout`, result-limit failures, and replica lag. Use
PostgreSQL-side telemetry for replica lag and pool or server saturation; Truster
does not expose dedicated metrics for them. Cache hit rates can also help
explain load on the policy database.
