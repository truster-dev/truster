#!/bin/bash
# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

set -eo pipefail
umask 077

# Userdata script for Debian stable, which sets up truster and Caddy on a fresh instance.
# Variables which you can set prior to invoking this script:
# TRUSTER_VERSION="latest"
# TRUSTER_SHA512="abc123..."
# CADDY_VERSION="latest"
# CADDY_SHA512="def456..."
# OIDC_ADDR="auth.example.com" # May include a port, such as auth.example.com:8443.
# TRUSTER_CONFIG='{"static_policy":{"clients":{}}}'
# RUN_DB_MIGRATIONS=false
# SSH=false
# FIREWALL=true
# AUTO_UPDATES=true

# === DO NOT EDIT BELOW ===

# Caddyfile content
read -r -d '' CADDYFILE <<'CADDYEOF' || true
${OIDC_ADDR} {
    reverse_proxy localhost:8080
    log {
        output file /var/log/caddy/access.log
        format filter {
            wrap json
            fields {
                request>uri query {
                    replace state REDACTED
                }
                resp_headers>Location delete
            }
        }
    }
}
CADDYEOF

# Security configuration
SSH="${SSH:-false}"
FIREWALL="${FIREWALL:-true}"
AUTO_UPDATES="${AUTO_UPDATES:-true}"
RUN_DB_MIGRATIONS="${RUN_DB_MIGRATIONS:-false}"

echo "=== Starting Installation ==="

# === Verify system dependencies ===
for command in curl tar sha512sum; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "ERROR: required command is unavailable: ${command}"
        exit 1
    fi
done
if [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
    echo "ERROR: system CA certificates are unavailable"
    exit 1
fi
if [ "${AUTO_UPDATES}" = "true" ] && ! command -v unattended-upgrade >/dev/null 2>&1; then
    echo "ERROR: unattended-upgrades is unavailable"
    exit 1
fi

# === Configure Firewall (if enabled) ===
if [ "${FIREWALL}" = "true" ]; then
    echo "Configuring firewall..."
    # Only allow HTTP/HTTPS
    if ! command -v ufw >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq ufw
    fi
    ufw --force disable
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 80/tcp
    ufw allow 443/tcp
    if [ "${SSH}" = "true" ]; then
        ufw allow 22/tcp
    fi
    ufw --force enable
fi

# === Configure SSH Access ===
if [ "${SSH}" = "true" ]; then
    # Harden SSH configuration
    echo "Hardening SSH configuration..."
    cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'SSH_EOF'
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
SSH_EOF
    systemctl reload ssh || true
else
    echo "Disabling SSH..."
    systemctl stop ssh || true
    systemctl disable ssh || true
fi

# Auto-detect architecture
echo "Detecting architecture..."
MACHINE_ARCH=$(uname -m)
case "${MACHINE_ARCH}" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: ${MACHINE_ARCH}"
        exit 1
        ;;
esac
echo "ARCH: ${ARCH}"

# === Install truster ===
# Resolve "latest" or empty to actual version
if [ -z "${TRUSTER_VERSION}" ] || [ "${TRUSTER_VERSION}" = "latest" ]; then
    echo "Fetching latest truster release..."
    TRUSTER_VERSION=$(curl -sSL https://api.github.com/repos/truster-dev/truster/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "Latest version: ${TRUSTER_VERSION}"
fi

echo "Installing truster ${TRUSTER_VERSION}..."

curl -L "https://github.com/truster-dev/truster/releases/download/${TRUSTER_VERSION}/truster_${TRUSTER_VERSION#v}_linux_${ARCH}.tar.gz" -o /tmp/truster.tar.gz

if [ -n "${TRUSTER_SHA512}" ]; then
    echo "Verifying truster checksum..."
    echo "${TRUSTER_SHA512}  /tmp/truster.tar.gz" | sha512sum -c -
    if [ $? -ne 0 ]; then
        echo "ERROR: truster checksum verification failed"
        exit 1
    fi
fi

tar -xzf /tmp/truster.tar.gz -C /tmp
mv /tmp/truster /usr/local/bin/truster
chmod +x /usr/local/bin/truster
rm /tmp/truster.tar.gz

if ! id -u truster >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /var/lib/truster -m truster
fi

mkdir -p /etc/truster
mkdir -p /opt/truster
chown truster:truster /var/lib/truster
chmod 700 /var/lib/truster

# === Install Caddy ===
# Resolve "latest" or empty to actual version
if [ -z "${CADDY_VERSION}" ] || [ "${CADDY_VERSION}" = "latest" ]; then
    echo "Fetching latest Caddy release..."
    CADDY_VERSION=$(curl -sSL https://api.github.com/repos/caddyserver/caddy/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "Latest version: ${CADDY_VERSION}"
fi

echo "Installing Caddy ${CADDY_VERSION}..."

curl -L "https://github.com/caddyserver/caddy/releases/download/${CADDY_VERSION}/caddy_${CADDY_VERSION#v}_linux_${ARCH}.tar.gz" -o /tmp/caddy.tar.gz

if [ -n "${CADDY_SHA512}" ]; then
    echo "Verifying Caddy checksum..."
    echo "${CADDY_SHA512}  /tmp/caddy.tar.gz" | sha512sum -c -
    if [ $? -ne 0 ]; then
        echo "ERROR: Caddy checksum verification failed"
        exit 1
    fi
fi

tar -xzf /tmp/caddy.tar.gz -C /tmp caddy
mv /tmp/caddy /usr/bin/caddy
chmod +x /usr/bin/caddy
rm /tmp/caddy.tar.gz

if ! id -u caddy >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /var/lib/caddy -m caddy
fi

mkdir -p /etc/caddy
mkdir -p /var/log/caddy
chown caddy:caddy /var/log/caddy
chown -R caddy:caddy /var/lib/caddy

# === Create configuration files ===
echo "Creating configuration files..."

# Write truster config (already a complete JSON document from Terraform)
install -o truster -g truster -m 0600 /dev/null /etc/truster/config.jsonc
printf '%s\n' "${TRUSTER_CONFIG}" > /etc/truster/config.jsonc

# Write Caddyfile (expand variables)
install -o root -g caddy -m 0640 /dev/null /etc/caddy/Caddyfile
cat > /etc/caddy/Caddyfile <<EOF
$(eval "echo \"${CADDYFILE}\"")
EOF

# === Install systemd services ===
echo "Installing systemd services..."

MIGRATION_EXEC_START_PRE=""
if [ "${RUN_DB_MIGRATIONS}" = "true" ]; then
    MIGRATION_EXEC_START_PRE="ExecStartPre=/usr/local/bin/truster migrate --config /etc/truster/config.jsonc"
fi

cat > /etc/systemd/system/truster.service <<EOF
[Unit]
Description=Truster Server
After=network.target

[Service]
Type=simple
User=truster
Group=truster
WorkingDirectory=/opt/truster
${MIGRATION_EXEC_START_PRE}
ExecStart=/usr/local/bin/truster serve --config /etc/truster/config.jsonc
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/truster
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy Web Server
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/var/lib/caddy
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# === Start services ===
echo "Starting services..."
systemctl daemon-reload
systemctl enable truster
systemctl enable caddy
systemctl start truster
systemctl start caddy

# === Log Installation Info ===
echo "=== Installation complete ==="
echo ""
echo "Configuration:"
echo "  Address:      ${OIDC_ADDR}"
echo "  Issuer URL:   https://${OIDC_ADDR}"
echo ""
echo "Status:"
systemctl status truster --no-pager || true
echo ""
systemctl status caddy --no-pager || true
echo ""
echo "Logs:"
echo "  truster: journalctl -u truster -f"
echo "  caddy:     journalctl -u caddy -f"
echo ""

# === Automatic System Updates ===
if [ "${AUTO_UPDATES}" = "true" ]; then
    echo "Enabling automatic security updates..."
    export DEBIAN_FRONTEND=noninteractive
    dpkg-reconfigure unattended-upgrades
fi
