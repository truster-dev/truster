#!/usr/bin/env bash
# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0
# Runs the shared-state end-to-end suite against two Truster replicas.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEX_IMAGE="ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462" # v2.45.1
POSTGRES_IMAGE="docker.io/library/postgres@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa" # 17.5-alpine3.22
PGBOUNCER_IMAGE="ghcr.io/cloudnative-pg/pgbouncer@sha256:fd6ce6214390a2ff90bde014c6e5bfa64c99fcca6b0bdd53a63be4865ee5b5ac" # v1.25.2
DEX_CONTAINER_NAME="truster-e2e-dex"
POSTGRES_CONTAINER_NAME="truster-e2e-postgres"
PGBOUNCER_CONTAINER_NAME="truster-e2e-pgbouncer"
DATABASE_NETWORK_NAME="truster-e2e-database"
DEX_SUBJECT="CiQwOGE4Njg0Yi1kYjg4LTRiNzMtOTBhOS0zY2QxNjYxZjU0NjYSBWxvY2Fs"
STATIC_TRUST_CLIENT_ID="static-ci-token-exchange-e2e"
STATIC_TRUST_CLIENT_SECRET="static-ci-token-exchange-e2e-secret"
STATIC_INTERACTIVE_CLIENT_ID="static-kubelogin-interactive-e2e"
DB_TRUST_CLIENT_ID="db-ci-token-exchange-e2e"
DB_TRUST_CLIENT_SECRET="db-ci-token-exchange-e2e-secret"
DB_TRUST_BINDING_ID="db-dex-ci-exchange-e2e"
DB_INTERACTIVE_CLIENT_ID="db-kubelogin-interactive-e2e"
ID_TOKEN_TYPE="urn:ietf:params:oauth:token-type:id_token"
OAUTH2C_VERSION="1.20.0"
JWT_PAYLOAD_FILTER='split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | . + ("=" * ((4 - (length % 4)) % 4)) | @base64d | fromjson'

TEST_PORTS=()
pick_port() {
    local port selected used
    while true; do
        port=$((20000 + RANDOM % 20000))
        used=false
        for selected in "${TEST_PORTS[@]:-}"; do
            if [ "$port" = "$selected" ]; then used=true; break; fi
        done
        if [ "$used" = false ] && ! (: < "/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            TEST_PORTS+=("$port")
            REPLY="$port"
            return
        fi
    done
}

pick_port; DEX_PORT="$REPLY"
pick_port; TRUSTER_ISSUER_PORT="$REPLY"
pick_port; TRUSTER_CALLBACK_PORT="$REPLY"
pick_port; TRUSTER_REPLICA_PORTS=("$REPLY")
pick_port; TRUSTER_REPLICA_PORTS+=("$REPLY")
DEX_ORIGIN="http://127.0.0.1:$DEX_PORT"
DEX_ISSUER="$DEX_ORIGIN/dex"
TRUSTER_ISSUER="http://127.0.0.1:$TRUSTER_ISSUER_PORT"
TRUSTER_TOKEN_URL="$TRUSTER_ISSUER/token"
TRUSTER_LISTEN_ADDRESS="127.0.0.1:$TRUSTER_CALLBACK_PORT"

E2E_HEADLESS="${E2E_HEADLESS:-}"
if [ -z "$E2E_HEADLESS" ]; then
    if [ -t 1 ]; then E2E_HEADLESS=false; else E2E_HEADLESS=true; fi
fi
case "$E2E_HEADLESS" in
    1|true) E2E_HEADLESS=true ;;
    0|false) E2E_HEADLESS=false ;;
    *) echo "ERROR: E2E_HEADLESS must be true or false"; exit 1 ;;
esac
export E2E_HEADLESS

echo "==> Checking prerequisites..."
for cmd in curl jq make go kubectl oauth2c openssl; do
    if ! command -v "$cmd" &> /dev/null; then
        if [ "$cmd" = oauth2c ]; then
            echo "ERROR: oauth2c is required; install it with: brew install oauth2c"
            exit 1
        fi
        echo "ERROR: Required command '$cmd' not found. Please install it first."
        exit 1
    fi
done

if ! oauth2c version 2>&1 | grep -Fq "oauth2c version $OAUTH2C_VERSION "; then
    echo "ERROR: oauth2c $OAUTH2C_VERSION is required"
    exit 1
fi

if ! kubectl oidc-login --version &> /dev/null 2>&1; then
    echo "ERROR: kubectl oidc-login plugin not found."
    echo "Install with: brew install kubelogin"
    exit 1
fi
if kubectl oidc-login get-token --help 2>&1 | grep -Fq -- '--oidc-pkce-method'; then
    KUBELOGIN_PKCE_ARGS=(--oidc-pkce-method=S256)
else
    KUBELOGIN_PKCE_ARGS=(--oidc-use-pkce)
fi

CONTAINER_CMD="${CONTAINER_CMD:-podman}"
if ! command -v "$CONTAINER_CMD" &> /dev/null; then
    CONTAINER_CMD=docker
    if ! command -v "$CONTAINER_CMD" &> /dev/null; then
        echo "ERROR: Neither podman nor docker found. Please install one."
        exit 1
    fi
fi

echo "==> E2E Test: Starting Dex and truster"

remove_test_containers() {
    $CONTAINER_CMD stop "$DEX_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD rm "$DEX_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD stop "$PGBOUNCER_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD rm "$PGBOUNCER_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD stop "$POSTGRES_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD rm "$POSTGRES_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD network rm "$DATABASE_NETWORK_NAME" 2>/dev/null || true
}

cleanup() {
    echo "==> Cleaning up..."
    for pid in "${TRUSTER_PIDS[@]:-}" "${TRUSTER_PROXY_PID:-}" "${OAUTH2C_PID:-}"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
    done
    remove_test_containers
    if [ -n "${E2E_TEMP_DIR:-}" ]; then
        rm -rf "$E2E_TEMP_DIR"
    fi
}

start_replicas() {
    TRUSTER_PIDS=()
    for replica in 0 1; do
        (
            cd "$E2E_TEMP_DIR"
            exec "$PROJECT_ROOT/bin/truster" serve --config "${TRUSTER_CONFIGS[$replica]}" --debug
        ) >> "${TRUSTER_LOGS[$replica]}" 2>&1 &
        TRUSTER_PIDS+=("$!")
    done
}

stop_replicas() {
    local pid
    for pid in "${TRUSTER_PIDS[@]:-}"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
    done
    for pid in "${TRUSTER_PIDS[@]:-}"; do
        if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; fi
    done
    TRUSTER_PIDS=()
}

wait_for_replicas() {
    local replica i ready
    for replica in 0 1; do
        ready=false
        for i in {1..30}; do
            if curl -sf "http://127.0.0.1:${TRUSTER_REPLICA_PORTS[$replica]}/healthz" >/dev/null; then ready=true; break; fi
            if ! kill -0 "${TRUSTER_PIDS[$replica]}" 2>/dev/null; then break; fi
            sleep 1
        done
        if [ "$ready" != true ]; then
            cat "${TRUSTER_LOGS[$replica]}"
            $CONTAINER_CMD logs "$PGBOUNCER_CONTAINER_NAME" 2>&1 || true
            echo "ERROR: truster replica $((replica + 1)) failed readiness"
            exit 1
        fi
    done
}

wait_for_proxy_health() {
    local expected="$1"
    local i status
    for i in {1..30}; do
        status="$(curl -sS -o /dev/null -w '%{http_code}' "$TRUSTER_ISSUER/healthz" || true)"
        if [ "$status" = "$expected" ]; then return 0; fi
        sleep 1
    done
    echo "ERROR: proxy health did not become HTTP $expected (last HTTP $status)"
    return 1
}

show_replica_logs() {
    cat "${TRUSTER_LOGS[@]}"
}

kubelogin_get_token() {
    local client_id="$1"
    local cache_dir="$2"
    local output_file="$3"
    local mode="$4"
    local -a mode_args

    case "$mode" in
        interactive)
            mode_args=(--browser-command="$BROWSER_COMMAND" --authentication-timeout-sec=300)
            ;;
        refresh)
            mode_args=(--skip-open-browser --authentication-timeout-sec=10)
            ;;
        *)
            echo "ERROR: Unknown kubelogin mode '$mode'"
            return 1
            ;;
    esac

    kubectl oidc-login get-token \
        --oidc-issuer-url="$TRUSTER_ISSUER" \
        --oidc-client-id="$client_id" \
        "${KUBELOGIN_PKCE_ARGS[@]}" \
        --listen-address="$TRUSTER_LISTEN_ADDRESS" \
        --token-cache-dir="$cache_dir" \
        "${mode_args[@]}" > "$output_file"
}

E2E_TEMP_DIR="$(mktemp -d)"
trap cleanup EXIT INT TERM
DEX_CONFIG="$E2E_TEMP_DIR/dex-config.yaml"
sed -e "s#http://127.0.0.1:5556#$DEX_ORIGIN#" \
    -e "s#http://127.0.0.1:18080#$TRUSTER_ISSUER#" \
    "$SCRIPT_DIR/dex-config.yaml" > "$DEX_CONFIG"

echo "==> Cleaning up any existing test containers..."
remove_test_containers
$CONTAINER_CMD network create "$DATABASE_NETWORK_NAME" >/dev/null

echo "==> Starting PostgreSQL policy database container..."
$CONTAINER_CMD run -d --name "$POSTGRES_CONTAINER_NAME" --network "$DATABASE_NETWORK_NAME" -p 55434:5432 \
    -e POSTGRES_PASSWORD=e2e-admin -e POSTGRES_DB=truster_e2e "$POSTGRES_IMAGE"
for i in {1..30}; do
    # The image uses a temporary socket-only server during first-time initialization.
    # Probe TCP so setup continues only after the final server has started.
    if $CONTAINER_CMD exec "$POSTGRES_CONTAINER_NAME" pg_isready -h 127.0.0.1 -U postgres -d truster_e2e >/dev/null 2>&1; then break; fi
    if [ "$i" -eq 30 ]; then echo "ERROR: PostgreSQL failed to start"; exit 1; fi
    sleep 1
done
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -U postgres -d truster_e2e >/dev/null < "$PROJECT_ROOT/examples/policy-db/postgresql.sql"
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -v db_interactive_client_id="$DB_INTERACTIVE_CLIENT_ID" \
    -v db_trust_client_id="$DB_TRUST_CLIENT_ID" \
    -v db_trust_binding_id="$DB_TRUST_BINDING_ID" \
    -v dex_subject="$DEX_SUBJECT" \
    -U postgres -d truster_e2e >/dev/null <<'SQL'
CREATE ROLE truster_policy LOGIN PASSWORD 'e2e-read-only';
CREATE ROLE truster_state_migration LOGIN PASSWORD 'e2e-migration';
CREATE ROLE truster_state LOGIN PASSWORD 'e2e-state';
INSERT INTO truster_policy.clients VALUES (:'db_interactive_client_id'), (:'db_trust_client_id');
-- Dex's mockCallback connector returns this fixed, non-configurable identity.
INSERT INTO truster_policy.users VALUES (:'db_interactive_client_id', 'kilgore@kilgore.trout', ARRAY['admins','developers']);
INSERT INTO truster_policy.trust_bindings VALUES (:'db_trust_client_id','dex',:'db_trust_binding_id','trusted:e2e:ci', jsonb_build_object('sub', jsonb_build_object('const', :'dex_subject')),'{}','{}',ARRAY['e2e:ci']);
GRANT CONNECT ON DATABASE truster_e2e TO truster_policy;
GRANT USAGE ON SCHEMA truster_policy TO truster_policy;
GRANT SELECT ON ALL TABLES IN SCHEMA truster_policy TO truster_policy;
GRANT CONNECT, CREATE ON DATABASE truster_e2e TO truster_state_migration;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO truster_state_migration;
GRANT CONNECT ON DATABASE truster_e2e TO truster_state;
SQL

cat > "$E2E_TEMP_DIR/pgbouncer.ini" <<EOF
[databases]
truster_e2e = host=$POSTGRES_CONTAINER_NAME port=5432 dbname=truster_e2e

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
pool_mode = transaction
max_prepared_statements = 0
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
EOF
cat > "$E2E_TEMP_DIR/pgbouncer-userlist.txt" <<'EOF'
"truster_policy" "e2e-read-only"
"truster_state" "e2e-state"
EOF

echo "==> Starting transaction-mode PgBouncer container..."
$CONTAINER_CMD run -d --name "$PGBOUNCER_CONTAINER_NAME" --network "$DATABASE_NETWORK_NAME" -p 55433:6432 \
    -v "$E2E_TEMP_DIR/pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro" \
    -v "$E2E_TEMP_DIR/pgbouncer-userlist.txt:/etc/pgbouncer/userlist.txt:ro" \
    "$PGBOUNCER_IMAGE"
for i in {1..30}; do
    if $CONTAINER_CMD exec "$PGBOUNCER_CONTAINER_NAME" pg_isready -h 127.0.0.1 -p 6432 -U truster_policy -d truster_e2e >/dev/null 2>&1; then break; fi
    if [ "$i" -eq 30 ]; then $CONTAINER_CMD logs "$PGBOUNCER_CONTAINER_NAME"; echo "ERROR: PgBouncer failed to start"; exit 1; fi
    sleep 1
done

echo "==> Starting Dex container..."
$CONTAINER_CMD run -d --rm --name "$DEX_CONTAINER_NAME" \
    -p "127.0.0.1:$DEX_PORT:5556" \
    -v "$DEX_CONFIG:/etc/dex/config.docker.yaml:ro" \
    "$DEX_IMAGE"

echo "==> Waiting for Dex to be ready..."
for i in {1..30}; do
    if curl -s "$DEX_ISSUER/.well-known/openid-configuration" > /dev/null 2>&1; then
        echo "==> Dex is ready!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Dex failed to start"
        exit 1
    fi
    sleep 1
done

echo "==> Building truster..."
cd "$PROJECT_ROOT"
make build

echo "==> Starting truster..."
export TRUSTER_SIGNING_KEY="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)"
export TRUSTER_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export TRUSTER_DEX_CREDENTIALS='{"client_id":"truster-interactive-e2e","client_secret":"truster-interactive-e2e-secret"}'
export TRUSTER_STATE_DB_URL='postgresql://truster_state:e2e-state@127.0.0.1:55433/truster_e2e?sslmode=disable'
export TRUSTER_POLICY_DB_URL='postgresql://truster_policy:e2e-read-only@127.0.0.1:55433/truster_e2e?sslmode=disable'
export TRUSTER_STATE_MIGRATION_DB_URL='postgresql://truster_state_migration:e2e-migration@127.0.0.1:55434/truster_e2e?sslmode=disable'
TRUSTER_LOGS=("$E2E_TEMP_DIR/truster-1.log" "$E2E_TEMP_DIR/truster-2.log")
TRUSTER_CONFIGS=("$E2E_TEMP_DIR/truster-1.jsonc" "$E2E_TEMP_DIR/truster-2.jsonc")
BROWSER_COMMAND="$SCRIPT_DIR/browser-command.sh"
# See README.md for sequence diagrams of both E2E login flows.

for replica in 0 1; do
    sed -e "s#\"http_listen_addr\": \"127.0.0.1:18080\"#\"http_listen_addr\": \"127.0.0.1:${TRUSTER_REPLICA_PORTS[$replica]}\"#" \
        -e "s#http://127.0.0.1:18080#$TRUSTER_ISSUER#g" \
        -e "s#http://127.0.0.1:5556/dex#$DEX_ISSUER#g" \
        -e "s#http://localhost:18000#http://localhost:$TRUSTER_CALLBACK_PORT#g" \
        "$SCRIPT_DIR/truster-config.jsonc" > "${TRUSTER_CONFIGS[$replica]}"
done

go build -o "$E2E_TEMP_DIR/proxy" "$PROJECT_ROOT/scripts/test-rr-proxy"

echo "==> Migrating PostgreSQL state database with the migration-only role..."
"$PROJECT_ROOT/bin/truster" migrate --config "${TRUSTER_CONFIGS[0]}"
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 -U postgres -d truster_e2e >/dev/null <<'SQL'
GRANT USAGE ON SCHEMA public TO truster_state;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO truster_state;
SQL

echo "==> Starting two truster replicas and the round-robin issuer proxy..."
start_replicas
wait_for_replicas
(cd "$E2E_TEMP_DIR" && exec ./proxy -listen "127.0.0.1:$TRUSTER_ISSUER_PORT" \
    "http://127.0.0.1:${TRUSTER_REPLICA_PORTS[0]}" \
    "http://127.0.0.1:${TRUSTER_REPLICA_PORTS[1]}") > "$E2E_TEMP_DIR/proxy.log" 2>&1 &
TRUSTER_PROXY_PID=$!
wait_for_proxy_health 200

echo "==> Testing RFC 9449 DPoP and RFC 9126 PAR interoperability with oauth2c..."
DPOP_KEY="$E2E_TEMP_DIR/dpop-key.jwks"
DPOP_TOKENS="$E2E_TEMP_DIR/dpop-tokens.json"
DPOP_REFRESHED_TOKENS="$E2E_TEMP_DIR/dpop-refreshed-tokens.json"
DPOP_AUTH_URL="$E2E_TEMP_DIR/dpop-authorization-url"
(cd "$PROJECT_ROOT/scripts/e2e/dpop-client" && go build -o "$E2E_TEMP_DIR/dpop-client" .)
DPOP_JKT="$("$E2E_TEMP_DIR/dpop-client" key "$DPOP_KEY")"
DIRECT_AUTH_RESPONSE="$E2E_TEMP_DIR/direct-authorization-response"
DIRECT_AUTH_STATUS="$(curl -sS -o "$DIRECT_AUTH_RESPONSE" -w '%{http_code}' --get \
    --data-urlencode 'client_id=static-dpop-par-e2e' \
    --data-urlencode "redirect_uri=http://localhost:$TRUSTER_CALLBACK_PORT/dpop-callback" \
    --data-urlencode 'response_type=code' \
    --data-urlencode 'scope=openid' \
    --data-urlencode 'code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM' \
    --data-urlencode 'code_challenge_method=S256' \
    --data-urlencode "dpop_jkt=$DPOP_JKT" \
    "$TRUSTER_ISSUER/authorize")"
if [ "$DIRECT_AUTH_STATUS" != 400 ] || ! grep -Fq 'pushed authorization request required' "$DIRECT_AUTH_RESPONSE"; then
    echo "ERROR: the PAR-required client accepted a direct authorization request"
    exit 1
fi
oauth2c "$TRUSTER_ISSUER" \
    --client-id=static-dpop-par-e2e \
    --grant-type=authorization_code \
    --response-types=code \
    --response-mode=query \
    --auth-method=none \
    --pkce \
    --par \
    --dpop \
    --signing-key="$DPOP_KEY" \
    --redirect-url="http://localhost:$TRUSTER_CALLBACK_PORT/dpop-callback" \
    --callback-addr="127.0.0.1:$TRUSTER_CALLBACK_PORT" \
    --scopes=openid \
    --no-browser \
    --silent > "$DPOP_TOKENS" 2> "$DPOP_AUTH_URL" &
OAUTH2C_PID=$!
for i in {1..100}; do
    if [ -s "$DPOP_AUTH_URL" ]; then break; fi
    if ! kill -0 "$OAUTH2C_PID" 2>/dev/null; then break; fi
    sleep 0.05
done
if [ ! -s "$DPOP_AUTH_URL" ]; then
    wait "$OAUTH2C_PID" || true
    echo "ERROR: oauth2c did not produce an authorization URL"
    cat "$DPOP_AUTH_URL"
    show_replica_logs
    exit 1
fi
CALLBACK_READY=false
for i in {1..100}; do
    if (: < "/dev/tcp/127.0.0.1/$TRUSTER_CALLBACK_PORT") 2>/dev/null; then
        CALLBACK_READY=true
        break
    fi
    if ! kill -0 "$OAUTH2C_PID" 2>/dev/null; then break; fi
    sleep 0.05
done
if [ "$CALLBACK_READY" != true ]; then
    wait "$OAUTH2C_PID" || true
    echo "ERROR: oauth2c callback listener did not become ready"
    cat "$DPOP_AUTH_URL"
    show_replica_logs
    exit 1
fi
if ! "$BROWSER_COMMAND" "$(head -n 1 "$DPOP_AUTH_URL")"; then
    show_replica_logs
    exit 1
fi
if ! wait "$OAUTH2C_PID"; then
    cat "$DPOP_AUTH_URL"
    show_replica_logs
    exit 1
fi
OAUTH2C_PID=""
if ! oauth2c "$TRUSTER_ISSUER" \
    --client-id=static-dpop-par-e2e \
    --grant-type=refresh_token \
    --auth-method=none \
    --refresh-token="$(jq -er '.refresh_token' "$DPOP_TOKENS")" \
    --dpop \
    --signing-key="$DPOP_KEY" \
    --silent > "$DPOP_REFRESHED_TOKENS"; then
    show_replica_logs
    exit 1
fi
if ! "$E2E_TEMP_DIR/dpop-client" exercise \
    "$TRUSTER_ISSUER" "$DPOP_KEY" "$DPOP_TOKENS" "$DPOP_REFRESHED_TOKENS"; then
    show_replica_logs
    exit 1
fi

echo "==> Testing OIDC discovery endpoint..."
if ! curl -sf "$TRUSTER_ISSUER/.well-known/openid-configuration" | jq . > /dev/null; then
    curl -sS -i "$TRUSTER_ISSUER/.well-known/openid-configuration" || true
    show_replica_logs
    echo "ERROR: Failed to get OIDC discovery document"
    exit 1
fi

echo "==> Testing JWKS endpoint..."
if ! curl -sf "$TRUSTER_ISSUER/jwks" | jq . > /dev/null; then
    echo "ERROR: Failed to get JWKS"
    exit 1
fi

echo "==> Testing statically configured OIDC federation..."
STATIC_DEX_TOKEN_RESPONSE="$E2E_TEMP_DIR/static-dex-token-response.json"
STATIC_DEX_TOKEN_STATUS="$(curl -sS -o "$STATIC_DEX_TOKEN_RESPONSE" -w '%{http_code}' \
    -u "$STATIC_TRUST_CLIENT_ID:$STATIC_TRUST_CLIENT_SECRET" \
    --data-urlencode grant_type=password \
    --data-urlencode username=test@example.com \
    --data-urlencode password=truster-e2e-password \
    --data-urlencode 'scope=openid email' \
    "$DEX_ISSUER/token")"
if [ "$STATIC_DEX_TOKEN_STATUS" != 200 ]; then
    echo "ERROR: Dex did not issue the static federation test token (HTTP $STATIC_DEX_TOKEN_STATUS)"
    exit 1
fi
STATIC_DEX_ID_TOKEN="$(jq -er '.id_token | select(type == "string" and length > 0)' "$STATIC_DEX_TOKEN_RESPONSE")"
STATIC_DEX_TOKEN_FILE="$E2E_TEMP_DIR/static-dex-id-token"
printf '%s' "$STATIC_DEX_ID_TOKEN" > "$STATIC_DEX_TOKEN_FILE"
chmod 600 "$STATIC_DEX_TOKEN_FILE"

if ! "$PROJECT_ROOT/bin/truster" check trust --config "${TRUSTER_CONFIGS[0]}" --client-id "$STATIC_TRUST_CLIENT_ID" --token-file "$STATIC_DEX_TOKEN_FILE" > /dev/null; then
    echo "ERROR: truster check trust rejected the static client token"
    exit 1
fi

STATIC_EXCHANGE_RESPONSE="$E2E_TEMP_DIR/static-token-exchange-response.json"
STATIC_EXCHANGE_STATUS="$(curl -sS -o "$STATIC_EXCHANGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "client_id=$STATIC_TRUST_CLIENT_ID" \
    --data-urlencode "subject_token=$STATIC_DEX_ID_TOKEN" \
    --data-urlencode "subject_token_type=$ID_TOKEN_TYPE" \
    --data-urlencode "requested_token_type=$ID_TOKEN_TYPE" \
    "$TRUSTER_TOKEN_URL")"
unset STATIC_DEX_ID_TOKEN
if [ "$STATIC_EXCHANGE_STATUS" != 200 ] || ! jq -e --arg audience "$STATIC_TRUST_CLIENT_ID" --arg issuer "$DEX_ISSUER" --arg subject "$DEX_SUBJECT" '
    .access_token |
    '"$JWT_PAYLOAD_FILTER"' |
    .sub == "trusted:e2e:static" and
    .aud == [$audience] and
    .groups == ["e2e:static"] and
    .upstream_issuer == $issuer and
    .upstream_subject == $subject
' "$STATIC_EXCHANGE_RESPONSE" > /dev/null; then
    echo "ERROR: static OIDC federation returned unexpected claims"
    exit 1
fi
echo "✅ Static trust policy and binding minted the expected service token."

echo "==> Testing static client, user group mapping, and refresh with kubelogin..."
STATIC_TOKEN_CACHE_DIR="$E2E_TEMP_DIR/static-cache"
STATIC_FIRST_TOKEN="$E2E_TEMP_DIR/static-first.json"
STATIC_SECOND_TOKEN="$E2E_TEMP_DIR/static-second.json"
mkdir -p "$STATIC_TOKEN_CACHE_DIR"
kubelogin_get_token "$STATIC_INTERACTIVE_CLIENT_ID" "$STATIC_TOKEN_CACHE_DIR" "$STATIC_FIRST_TOKEN" interactive

if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["static-admins", "static-developers"]
' "$STATIC_FIRST_TOKEN" >/dev/null; then
    echo "ERROR: static client ID token did not contain configured user group mapping"
    exit 1
fi

sleep 6
kubelogin_get_token "$STATIC_INTERACTIVE_CLIENT_ID" "$STATIC_TOKEN_CACHE_DIR" "$STATIC_SECOND_TOKEN" refresh

if [ "$(jq -r '.status.token // empty' "$STATIC_FIRST_TOKEN")" = "$(jq -r '.status.token // empty' "$STATIC_SECOND_TOKEN")" ]; then
    echo "ERROR: static client refresh did not return a fresh ID token"
    exit 1
fi
if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["static-admins", "static-developers"]
' "$STATIC_SECOND_TOKEN" >/dev/null; then
    echo "ERROR: refreshed static client token did not preserve configured user group mapping"
    exit 1
fi
if ! jq -s -e --arg client "$STATIC_INTERACTIVE_CLIENT_ID" 'any(.[]; .msg == "refresh attempt" and .result == 200 and .client_id == $client)' "${TRUSTER_LOGS[@]}" > /dev/null; then
    show_replica_logs
    echo "ERROR: no successful static client refresh exchange was logged"
    exit 1
fi
if jq -s -e --arg trust "$STATIC_TRUST_CLIENT_ID" --arg interactive "$STATIC_INTERACTIVE_CLIENT_ID" 'any(.[]; .msg == "policy database query" and (.client_id == $trust or .client_id == $interactive))' "${TRUSTER_LOGS[@]}" > /dev/null; then
    show_replica_logs
    echo "ERROR: a statically configured client caused a policy database query"
    exit 1
fi
echo "✅ Static client user group mapping and refresh succeeded without policy database queries."

echo "==> Testing trusted service login with database policy..."
DB_DEX_TOKEN_RESPONSE="$E2E_TEMP_DIR/db-dex-token-response.json"
DB_DEX_TOKEN_STATUS="$(curl -sS -o "$DB_DEX_TOKEN_RESPONSE" -w '%{http_code}' \
    -u "$DB_TRUST_CLIENT_ID:$DB_TRUST_CLIENT_SECRET" \
    --data-urlencode grant_type=password \
    --data-urlencode username=test@example.com \
    --data-urlencode password=truster-e2e-password \
    --data-urlencode 'scope=openid email' \
    "$DEX_ISSUER/token")"
if [ "$DB_DEX_TOKEN_STATUS" != 200 ]; then
    echo "ERROR: Dex did not issue the trusted service test token for the database policy flow (HTTP $DB_DEX_TOKEN_STATUS)"
    exit 1
fi
DB_DEX_ID_TOKEN="$(jq -er '.id_token | select(type == "string" and length > 0)' "$DB_DEX_TOKEN_RESPONSE")"
DB_DEX_TOKEN_FILE="$E2E_TEMP_DIR/db-dex-id-token"
printf '%s' "$DB_DEX_ID_TOKEN" > "$DB_DEX_TOKEN_FILE"
chmod 600 "$DB_DEX_TOKEN_FILE"

if ! "$PROJECT_ROOT/bin/truster" check trust --config "${TRUSTER_CONFIGS[0]}" --client-id "$DB_TRUST_CLIENT_ID" --token-file "$DB_DEX_TOKEN_FILE" > /dev/null; then
    echo "ERROR: truster check trust rejected the client supplied by database policy"
    exit 1
fi

DB_EXCHANGE_RESPONSE="$E2E_TEMP_DIR/db-token-exchange-response.json"
DB_EXCHANGE_HEADERS="$E2E_TEMP_DIR/db-token-exchange-headers.txt"
DB_EXCHANGE_STATUS="$(curl -sS -D "$DB_EXCHANGE_HEADERS" -o "$DB_EXCHANGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "client_id=$DB_TRUST_CLIENT_ID" \
    --data-urlencode "subject_token=$DB_DEX_ID_TOKEN" \
    --data-urlencode "subject_token_type=$ID_TOKEN_TYPE" \
    --data-urlencode "requested_token_type=$ID_TOKEN_TYPE" \
    "$TRUSTER_TOKEN_URL")"
unset DB_DEX_ID_TOKEN
if [ "$DB_EXCHANGE_STATUS" != 200 ]; then
    show_replica_logs
    echo "ERROR: Truster rejected the trusted service login using database policy (HTTP $DB_EXCHANGE_STATUS)"
    exit 1
fi
if ! grep -Eiq '^cache-control:[[:space:]]*no-store[[:space:]]*$' "$DB_EXCHANGE_HEADERS" ||
   ! grep -Eiq '^pragma:[[:space:]]*no-cache[[:space:]]*$' "$DB_EXCHANGE_HEADERS"; then
    echo "ERROR: trusted service login using database policy is missing no-cache headers"
    exit 1
fi
if ! jq -e --arg token_type "$ID_TOKEN_TYPE" '
    (.access_token | type == "string" and length > 0) and
    .issued_token_type == $token_type and
    .token_type == "Bearer" and
    (.expires_in | type == "number" and . > 0 and . <= 900) and
    (has("id_token") | not) and
    (has("refresh_token") | not)
' "$DB_EXCHANGE_RESPONSE" > /dev/null; then
    echo "ERROR: trusted service login using database policy returned an invalid token response"
    exit 1
fi

DB_MINTED_TOKEN_PAYLOAD="$(jq -er '
    .access_token |
    '"$JWT_PAYLOAD_FILTER"'
' "$DB_EXCHANGE_RESPONSE")"
if ! jq -e \
    --arg audience "$DB_TRUST_CLIENT_ID" \
    --arg issuer "$DEX_ISSUER" \
    --arg subject "$DEX_SUBJECT" '
    .sub == "trusted:e2e:ci" and
    .aud == [$audience] and
    .groups == ["e2e:ci"] and
    .upstream_issuer == $issuer and
    .upstream_subject == $subject and
    (.jti | type == "string" and length > 0) and
    (has("sid") | not)
' <<< "$DB_MINTED_TOKEN_PAYLOAD" > /dev/null; then
    jq . <<< "$DB_MINTED_TOKEN_PAYLOAD"
    echo "ERROR: trusted service token produced with database policy contains unexpected claims"
    exit 1
fi
unset DB_MINTED_TOKEN_PAYLOAD
echo "✅ Database policy supplied the expected trusted service token."

echo "==> Mutating the live policy database trust binding and exchanging again..."
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -v db_trust_binding_id="$DB_TRUST_BINDING_ID" -U postgres -d truster_e2e >/dev/null <<'SQL'
UPDATE truster_policy.trust_bindings SET subject='trusted:e2e:changed', groups=ARRAY['e2e:changed'] WHERE binding_id=:'db_trust_binding_id';
SQL
DB_MUTATED_EXCHANGE_RESPONSE="$E2E_TEMP_DIR/db-mutated-exchange-response.json"
DB_MUTATED_EXCHANGE_STATUS="$(curl -sS -o "$DB_MUTATED_EXCHANGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "client_id=$DB_TRUST_CLIENT_ID" \
    --data-urlencode "subject_token=$(cat "$DB_DEX_TOKEN_FILE")" \
    --data-urlencode "subject_token_type=$ID_TOKEN_TYPE" \
    --data-urlencode "requested_token_type=$ID_TOKEN_TYPE" "$TRUSTER_TOKEN_URL")"
if [ "$DB_MUTATED_EXCHANGE_STATUS" != 200 ] || ! jq -e '
    .access_token |
    '"$JWT_PAYLOAD_FILTER"' |
    .sub == "trusted:e2e:changed" and
    .groups == ["e2e:changed"]
' "$DB_MUTATED_EXCHANGE_RESPONSE" >/dev/null; then
    echo "ERROR: changed database policy trust output was not applied"
    exit 1
fi

echo "==> Testing OIDC login and refresh with database policy..."
printf '\nOpening browser for OIDC authentication...\n'
printf 'Please complete the login in your browser (use Dex mock login)\n\n'

DB_TOKEN_CACHE_DIR="$E2E_TEMP_DIR/db-cache"
DB_FIRST_TOKEN="$E2E_TEMP_DIR/db-first.json"
DB_SECOND_TOKEN="$E2E_TEMP_DIR/db-second.json"
mkdir -p "$DB_TOKEN_CACHE_DIR"
kubelogin_get_token "$DB_INTERACTIVE_CLIENT_ID" "$DB_TOKEN_CACHE_DIR" "$DB_FIRST_TOKEN" interactive

if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["admins", "developers"]
' "$DB_FIRST_TOKEN" >/dev/null; then
    echo "ERROR: ID token for a client supplied by database policy did not contain initial groups"
    exit 1
fi

echo "==> Waiting for the initial ID token to expire..."
sleep 6

echo "==> Restarting both truster replicas before refresh to prove PostgreSQL state persistence..."
stop_replicas
start_replicas
wait_for_replicas
wait_for_proxy_health 200
if find "$E2E_TEMP_DIR" -type f -name '*.db' | grep -q .; then
    echo "ERROR: SQLite state file was created while PostgreSQL state was configured"
    exit 1
fi

echo "==> Updating live user groups in the policy database before refresh..."
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -v db_interactive_client_id="$DB_INTERACTIVE_CLIENT_ID" -U postgres -d truster_e2e >/dev/null <<'SQL'
UPDATE truster_policy.users SET groups=ARRAY['current-on-refresh'] WHERE client_id=:'db_interactive_client_id';
SQL

echo "==> Refreshing without opening a browser..."
kubelogin_get_token "$DB_INTERACTIVE_CLIENT_ID" "$DB_TOKEN_CACHE_DIR" "$DB_SECOND_TOKEN" refresh

if [ "$(jq -r '.status.token // empty' "$DB_FIRST_TOKEN")" = "$(jq -r '.status.token // empty' "$DB_SECOND_TOKEN")" ]; then
    echo "ERROR: kubelogin did not return a fresh ID token"
    exit 1
fi
if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["current-on-refresh"]
' "$DB_SECOND_TOKEN" >/dev/null; then
    echo "ERROR: refreshed ID token did not contain current database policy groups"
    exit 1
fi
if ! jq -s -e --arg client "$DB_INTERACTIVE_CLIENT_ID" 'any(.[]; .msg == "refresh attempt" and .result == 200 and .client_id == $client)' "${TRUSTER_LOGS[@]}" > /dev/null; then
    show_replica_logs
    echo "ERROR: no successful kubelogin refresh exchange was logged"
    exit 1
fi

printf '\n✅ ID token received and refreshed by kubelogin without another browser login.\n'

echo "==> Stopping PostgreSQL to verify fail-closed behavior and live recovery..."
$CONTAINER_CMD stop "$POSTGRES_CONTAINER_NAME" >/dev/null
wait_for_proxy_health 503
OUTAGE_RESPONSE="$E2E_TEMP_DIR/outage-response"
OUTAGE_STATUS="$(curl -sS -o "$OUTAGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode grant_type=refresh_token \
    --data-urlencode client_id="$DB_INTERACTIVE_CLIENT_ID" \
    --data-urlencode refresh_token='ert1.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    "$TRUSTER_TOKEN_URL" || true)"
if [ "$OUTAGE_STATUS" -lt 500 ] || grep -Eiq 'postgres|truster|127\.0\.0\.1|55434|e2e-state|password' "$OUTAGE_RESPONSE"; then
    cat "$OUTAGE_RESPONSE"
    echo "ERROR: stateful operation did not fail closed without database details (HTTP $OUTAGE_STATUS)"
    exit 1
fi

echo "==> Restarting PostgreSQL and waiting for replicas to recover without restart..."
$CONTAINER_CMD start "$POSTGRES_CONTAINER_NAME" >/dev/null
for i in {1..30}; do
    if $CONTAINER_CMD exec "$POSTGRES_CONTAINER_NAME" pg_isready -h 127.0.0.1 -U postgres -d truster_e2e >/dev/null 2>&1; then break; fi
    if [ "$i" -eq 30 ]; then echo "ERROR: PostgreSQL failed to recover"; exit 1; fi
    sleep 1
done
wait_for_replicas
wait_for_proxy_health 200
echo "✅ Both replicas failed closed during the database outage and recovered in place."
printf '\n✅ E2E Test PASSED!\n'
