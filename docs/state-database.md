---
title: 'State Database'
weight: 8
---

# State database

By default, Truster uses SQLite for persisting OIDC protocol state such as
authorization codes, OTPs, and refresh grants. This is the easiest option
for one Truster replica.

For multiple replicas, use PostgreSQL so every replica shares temporary browser
and authorization-code state as well as refresh grants. The
state database is operational protocol storage. It is separate from the
optional read-only [policy database](policy-database.md), which supplies clients,
users, groups, and trust policy.

## Configuration

If `state_database` is omitted, it uses `./data/truster-state.db` e.g:

```jsonc
"state_database": {
  "driver": "sqlite",
  "path": "/var/lib/truster/truster-state.db"
}
```

Set an absolute `path` in production. SQLite is suitable for one Truster
replica.

To use PostgreSQL, explicitly configure `state_database` with the
`postgresql` driver and relevant settings:

```jsonc
"state_database": {
  "driver": "postgresql",
  "connection_string_secret": "TRUSTER_STATE_DB_URL",
  "max_connections": 16,
  "query_timeout": "5s",
  "migrations": {
    "connection_string_secret": "TRUSTER_STATE_MIGRATION_DB_URL"
  }
}
```

## Run migrations before deployment

Before every new version rollout, run:

```console
truster migrate --config config.jsonc
```

Migrations are forward-only. Truster refuses to start when the schema is
missing, dirty, older, or newer than the binary expects.

When using transaction-mode PgBouncer, point the runtime
`connection_string_secret` at PgBouncer and the migration-only secret directly
at PostgreSQL. Do not run migrations through PgBouncer: schema changes can be
long-running and should retain a direct connection. Runtime state queries are
schema-qualified and do not depend on session settings or persistent prepared
statements, so transactions, row locks, and transaction advisory locks remain
safe through transaction pooling.

DPoP replay hashes are not protocol state and are not written to this database. Each
process keeps an independent bounded in-memory cache for the 15-second proof acceptance
window. Replays reaching the same process are rejected; detection across replicas is
best-effort. The durable database protections remain the single-use PAR and
authorization-code operations, refresh-token rotation, and idempotent revocation. See
the [DPoP integration guide](dpop.md) for the complete operational contract.

In the uncommon event of a migration failing:

- stop the rollout;
- investigate the failed statement and restore from backup if necessary; and
- repair dirty migration metadata only after confirming the schema state—never
  guess a version.

## Use separate database roles

For least privilege, give migration and runtime operations different roles:

- **Migration role:** database `CREATE`, `USAGE, CREATE` on `public`, and
  ownership of `public.schema_migrations` and `truster_state`.
- **Runtime role:** database `CONNECT`, `USAGE` on `public` and
  `truster_state`, `SELECT` on `public.schema_migrations`, and `SELECT`,
  `INSERT`, `UPDATE`, `DELETE` on every state table.

`USAGE` on `public` is still required if its default PUBLIC privilege has been
revoked. Reapply runtime table grants after migrations when needed.

The AWS and Google Cloud OpenTofu/Terraform modules leave migration-only
credentials off the VM by default. Set the module input `run_db_migrations` to
`true` to grant the VM access to the configured migration secret. The module
passes this input to `deploy/userdata.sh` as `RUN_DB_MIGRATIONS`, which runs
`truster migrate` before every service start. This is a module input, not a
field in the Truster configuration. A failed migration prevents the service
from starting. Keep the default and migrate from your deployment pipeline when
the application VM should not hold the more privileged migration credential.

## Production checklist

- Require certificate-verified TLS. Plaintext connections are accepted only on
  loopback addresses for development.
- With direct connections, set `max_connections` per replica so their combined
  pools remain below the PostgreSQL limit. With PgBouncer, keep the combined
  application pools below its client limit and size its server pool for measured
  database concurrency. In either case, reserve direct capacity for migrations
  and administration.
- Choose a `query_timeout` that covers expected database latency. It bounds pool
  waits and queries; an unavailable or exhausted database fails readiness.
- Give every replica the same issuer, signing key, encryption key, OTP secret,
  connector credentials, and state database.
- Back up the state schema and migration metadata together, and test
  point-in-time recovery. Restore signing and encryption secrets from their
  secret manager. In-flight logins may be lost at the recovery boundary.

## Move from SQLite

There is no online importer:

1. Drain traffic and stop all Truster replicas.
2. Let short-lived authorization state expire.
3. Configure PostgreSQL and run the migration command.
4. Start every replica with the shared configuration and secrets.
5. Require users with existing refresh grants to sign in again.

Retire the old SQLite file. Never reuse it as a rollback target because it could
revive consumed codes or revoked grants. A rollback must use a new, empty SQLite
database, and SQLite and PostgreSQL replicas must never run concurrently.
