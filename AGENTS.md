<!--
Truster <https://truster.dev>
Copyright The Truster Authors
SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

This file contains guidance for AI coding agents working on the truster project.

## Frequently Used Commands

### Build
```bash
make setup          # Verify tools and install Git hooks
make build          # Build the binary
make image          # Package prebuilt Linux binaries with ocimage
make clean          # Clean build artifacts
```

`make build` accepts standard `GOOS`, `GOARCH`, and `CC` settings plus
`BUILD_OUTPUT`, `BUILD_TAGS`, and `BUILD_EXTRA_LDFLAGS`. Before `make image`,
build each architecture selected by `IMAGE_ARCHES` into
`bin/linux_<arch>/truster`.

### Testing
```bash
make test           # Run all tests with race detector
go test ./...       # Run tests
go test -v ./...    # Run tests verbosely
make e2e            # Run E2E test with Dex container as upstream
```

### Code Quality
```bash
make fmt            # Format code
make lint           # Run linter
make precommit      # Check formatting and lint without modifying files
make helm-validate  # Lint, render, and validate the Helm chart
make check          # Run fmt, lint, and test
```

### Development
```bash
# Run locally with example config
./bin/truster serve --config examples/config/config-local-dev.jsonc --debug

# Validate configuration and templates
./bin/truster check config --config config.jsonc
./bin/truster check templates --config config.jsonc

# Show version
./bin/truster --version
```

## Project Structure

```
.
├── cmd/truster/          # Main entry point
├── internal/
│   ├── buildvars/          # Build version info
│   ├── cmd/                # Cobra CLI commands
│   ├── config/             # Configuration loading and validation
│   ├── secrets/            # Secrets providers (AWS, GCP, Azure, env)
│   ├── oidc/               # OIDC server and handlers
│   ├── statedb/            # SQLite/PostgreSQL OAuth protocol state
│   ├── upstream/           # Google/GitHub connectors
│   └── tokens/             # Token signing, JWKS, groups
├── examples/               # Example configs and deployment files
├── deploy/helm/            # Kubernetes application chart
├── images/truster/       # Packaging-only ocimage definition
└── scripts/                # Helper scripts, automation, and Git hooks
```

## Generated Files

The trust policy schema bundle under `schema/v2/` is generated from the runtime rules with `make schemas` and must remain committed. `make precommit` checks that it is current. Go module sums are maintained by Go module commands and must remain committed. Build output, image binaries, the staged image CA bundle, coverage, and temporary SQLite data belong under ignored paths and are removed by `make clean`.

## Code Conventions

- Use `slog` for structured logging
- All errors should be wrapped with context using `fmt.Errorf`
- Configuration validation happens at startup
- Secrets are loaded once at startup (not on every request)
- Email addresses are always normalized to lowercase
- PKCE is mandatory for all clients
- No downstream client secrets (downstream clients are public and use PKCE)
- Every Go package must define its package docblock in `doc.go`
- Every new Go function, method, and type must have a docblock comment, even if unexported

## Key Design Decisions

- **Kubernetes-compatible signing**: RS256 by default; all Kubernetes-supported asymmetric algorithms plus EdDSA are available
- **Opaque auth codes**: Cryptographically random, single-use values stored in the state database
- **No sessions or cookies**: Browser state and authorization codes are persisted in the state database, not client sessions
- **Email as `sub` claim**: Human-readable, stable across IdP changes
- **Single-use auth codes**: Atomically consumed from the state database with expiry

## Upstream Connectors

truster supports multiple upstream OAuth2/OIDC providers:

- **Google**: Built-in Google OAuth2 with hosted domain support
- **GitHub**: Built-in GitHub OAuth2 with GitHub Enterprise support
- **Generic**: Generic OAuth2/OIDC provider support for Dex, Keycloak, Auth0, etc.

## Dependencies

- `github.com/lestrrat-go/jwx/v2` - JWT/JWK/JWKS handling
- `golang.org/x/oauth2` - OAuth2 client for Google/GitHub
- `github.com/tailscale/hujson` - JSONC config parsing
- `github.com/spf13/cobra` - CLI framework
- Cloud SDKs for secrets management (AWS, GCP, Azure)

## Adding New Features

When adding features:
1. Update config types in `internal/config/types.go`
2. Add validation in `internal/config/loader.go`
3. Write tests for new functionality
4. Update example configs in `examples/config/`
5. Run `make check` before committing
