# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help

VERSION_TAG := $(shell if [ -z "$$(git status --porcelain)" ]; then tag=$$(git describe --tags --exact-match 2>/dev/null); echo "$$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' && echo "$$tag"; fi)
BUILD_VERSION := $(if $(VERSION_TAG),$(VERSION_TAG),dev)
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT_HASH := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
COMMIT_DATE := $(shell TZ=UTC git log -1 --format=%cd --date=format-local:'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)
COMMIT_BRANCH := $(shell branch=$$(git symbolic-ref --short -q HEAD); if [ -n "$$branch" ]; then echo "$$branch"; else echo unknown; fi)

BUILDVARS_PKG := github.com/truster-dev/truster/v2/internal/buildvars

BINARY_DIR := bin
OCIMAGE ?= ocimage
IMAGE_ARCHES ?= amd64,arm64
IMAGE_PLATFORMS := $(shell printf '%s' '$(IMAGE_ARCHES)' | tr -d ' ' | sed 's/[^,][^,]*/linux\/&/g')
IMAGE_TAGS ?= ghcr.io/truster-dev/truster:$(patsubst v%,%,$(BUILD_VERSION))
IMAGE_PUSH ?= false
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
BUILD_OUTPUT ?= $(BINARY_DIR)/truster
BUILD_TAGS ?=
BUILD_EXTRA_LDFLAGS ?=
# Kubeconform only bundles schemas for native Kubernetes resources. Resolve
# schemas for rendered CRDs, including cert-manager Certificate, from Datree's
# CRDs catalog. Pin the catalog commit so validation is reproducible.
KUBECONFORM_CRD_SCHEMA_LOCATION := https://raw.githubusercontent.com/datreeio/CRDs-catalog/52b0261318acc7dd0b66e032759b1f218216b980/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json

# SQLite requires CGO
export CGO_ENABLED=1

LDFLAGS := -X $(BUILDVARS_PKG).buildVersion=$(BUILD_VERSION) \
           -X $(BUILDVARS_PKG).buildDate=$(BUILD_DATE) \
           -X $(BUILDVARS_PKG).commitHash=$(COMMIT_HASH) \
           -X $(BUILDVARS_PKG).commitDate=$(COMMIT_DATE) \
           -X $(BUILDVARS_PKG).commitBranch=$(COMMIT_BRANCH)

.PHONY: help setup fmt lint precommit test test-postgresql e2e check build image helm-lint helm-validate dev clean tag

help: ## Show available targets
	@echo "Usage: make <target>"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Verify required tools and install git hooks
	@command -v go >/dev/null 2>&1 || { echo "go is required but not installed"; exit 1; }
	@command -v cc >/dev/null 2>&1 || { echo "a C compiler is required but not installed"; exit 1; }
	@go tool golangci-lint version >/dev/null 2>&1 || { echo "golangci-lint is required as a Go tool"; exit 1; }
	@echo "All required tools are installed."
	@echo "Installing git hooks..."
	@mkdir -p .git/hooks
	@cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@cp scripts/git-hooks/commit-msg .git/hooks/commit-msg
	@chmod +x .git/hooks/commit-msg
	@echo "Setup complete. Git hooks installed."

fmt: ## Format Go source files
	@echo "Formatting code..."
	go fmt ./...

lint: ## Run golangci-lint
	@echo "Running linter..."
	go tool golangci-lint run

precommit: ## Check modules, formatting, and linters (read-only)
	@echo "Checking module files..."
	@go mod tidy -diff
	@echo "Checking formatting..."
	@UNFORMATTED=$$(gofmt -l . 2>&1); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "The following files need formatting (run 'make fmt'):"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi
	@$(MAKE) lint

test: ## Run tests with race detector
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

test-postgresql: ## Start/reuse local PostgreSQL and run real state database tests
	@set -e; CONTAINER_CMD=$${CONTAINER_CMD:-$$(command -v podman || command -v docker)}; test -n "$$CONTAINER_CMD" || { echo "podman or docker is required"; exit 1; }; \
	$$CONTAINER_CMD inspect truster-state-test >/dev/null 2>&1 || $$CONTAINER_CMD run -d --name truster-state-test -p 55435:5432 -e POSTGRES_USER=truster -e POSTGRES_PASSWORD=truster -e POSTGRES_DB=truster_state docker.io/library/postgres@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa >/dev/null; \
	$$CONTAINER_CMD start truster-state-test >/dev/null 2>&1 || true; \
	ready=0; for i in $$(seq 1 30); do $$CONTAINER_CMD exec truster-state-test pg_isready -U truster -d truster_state >/dev/null 2>&1 && ready=1 && break; sleep 1; done; \
	test "$$ready" = 1 || { echo "PostgreSQL did not become ready"; exit 1; }; \
	TRUSTER_STATE_TEST_DIRECT_DB_URL='postgresql://truster:truster@127.0.0.1:55435/truster_state?sslmode=disable' go test -v -race -count=1 ./internal/statedb -run PostgreSQL

e2e: ## Run E2E tests with Dex upstream
	@echo "Running E2E tests..."
	./scripts/e2e/run-e2e-test.sh

check: fmt lint test ## Format, lint, and test

build: ## Build the truster binary
	@echo "Building truster..."
	@mkdir -p "$(dir $(BUILD_OUTPUT))"
	@rm -f "$(BUILD_OUTPUT)"
	CGO_ENABLED="$(CGO_ENABLED)" GOOS="$(GOOS)" GOARCH="$(GOARCH)" CC="$(CC)" go build \
		-trimpath \
		$(if $(strip $(BUILD_TAGS)),-tags="$(BUILD_TAGS)",) \
		-ldflags="$(BUILD_EXTRA_LDFLAGS) $(LDFLAGS)" \
		-o "$(BUILD_OUTPUT)" \
		./cmd/truster

image: ## Package prebuilt architecture-specific binaries as an OCI image
	@set -eu; \
	for arch in $$(printf '%s' '$(IMAGE_ARCHES)' | tr ',' ' '); do \
		binary="$(BINARY_DIR)/linux_$$arch/truster"; \
		test -x "$$binary" || { \
			echo "prebuilt image binary not found or not executable: $$binary" >&2; \
			echo "run make build for linux/$$arch before make image" >&2; \
			exit 1; \
		}; \
	done
	$(OCIMAGE) build \
		--file images/truster/Containerfile \
		--platform $(IMAGE_PLATFORMS) \
		$(foreach tag,$(IMAGE_TAGS),--tag $(tag)) \
		--build-arg VERSION=$(BUILD_VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg COMMIT_HASH=$(COMMIT_HASH) \
		$(if $(filter true,$(IMAGE_PUSH)),--push,) \
		.

helm-lint: ## Lint the Truster Helm chart
	@command -v helm >/dev/null 2>&1 || { echo "helm is required but not installed"; exit 1; }
	helm lint --strict deploy/helm --set config.existingConfigMap=truster-config

helm-validate: helm-lint ## Render and validate representative Helm configurations
	@command -v kubeconform >/dev/null 2>&1 || { echo "kubeconform is required but not installed"; exit 1; }
	bash -o pipefail -c 'helm template truster deploy/helm \
		--set config.existingConfigMap=truster-config \
		| kubeconform -strict -summary -kubernetes-version 1.34.0 \
			-schema-location default -schema-location "$(KUBECONFORM_CRD_SCHEMA_LOCATION)"'
	bash -o pipefail -c 'helm template truster deploy/helm \
		--values tests/helm/generated-config-values.yaml \
		| kubeconform -strict -summary -kubernetes-version 1.34.0 \
			-schema-location default -schema-location "$(KUBECONFORM_CRD_SCHEMA_LOCATION)"'
	bash -o pipefail -c 'helm template truster deploy/helm \
		--values tests/helm/generated-config-values.yaml \
		--set config.state_database.driver=postgresql \
		--set config.state_database.connection_string_secret=TRUSTER_STATE_DB_URL \
		--set replicaCount=2 \
		--set deploymentStrategy.type=RollingUpdate \
		| kubeconform -strict -summary -kubernetes-version 1.34.0 \
			-schema-location default -schema-location "$(KUBECONFORM_CRD_SCHEMA_LOCATION)"'

dev: ## Run the template development server
	go run ./cmd/truster dev --templates-dir ./templates

clean: ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)/
	rm -rf temp/
	rm -f coverage.out

tag: ## Tag the current commit with a version (VERSION=vX.Y.Z)
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make tag VERSION=v1.0.0"; \
		exit 1; \
	elif ! echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$'; then \
		echo "VERSION must be a semantic version tag such as v1.2.3"; \
		exit 1; \
	fi; \
	[ -z "$$(git status --porcelain)" ] || { echo "Working tree must be clean before tagging"; exit 1; }; \
	git tag -a $(VERSION) -m "$(VERSION)"; \
	echo "Tagged $(VERSION)"; \
	echo ""; \
	echo "To push the tag, run:"; \
	echo "  git push origin $(VERSION)"
