# terraform-google-truster

OpenTofu/Terraform module for deploying [Truster](https://github.com/truster-dev/truster) on Google Cloud.

The module provisions a single Compute Engine instance, Caddy with automatic TLS, optional dual-stack networking, local SQLite storage, and Google Secret Manager access. Application settings are supplied directly as an Truster configuration object.

## Features

- Single Compute Engine instance (`e2-micro` by default)
- Optional public IPv4 and IPv6 addresses
- Optional automatic subnetwork creation
- Caddy with automatic Let's Encrypt TLS
- Google Secret Manager access through a dedicated or existing service account
- Optional customer-managed boot-disk encryption and SSH access

## Prerequisites

Enable the required Google Cloud APIs:

```bash
gcloud services enable \
  compute.googleapis.com \
  iam.googleapis.com \
  secretmanager.googleapis.com \
  cloudresourcemanager.googleapis.com
```

If using the Cloud DNS resources in the example, also enable `dns.googleapis.com`.

Create an OAuth credentials secret containing JSON such as:

```bash
cat > google-credentials.json <<'JSON'
{"client_id":"123456789.apps.googleusercontent.com","client_secret":"GOCSPX-xxxxxxxxxxxxxxxxxxxxx"}
JSON
gcloud secrets create truster-google \
  --replication-policy=automatic \
  --data-file=google-credentials.json
rm google-credentials.json
```

Create a signing-key secret containing a PKCS8 PEM private key. For example:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | \
  gcloud secrets create truster-signing-key \
    --replication-policy=automatic \
    --data-file=-
```

Create the 32-byte encryption master key too:

```bash
openssl rand -hex 32 | \
  gcloud secrets create truster-encryption-key \
    --replication-policy=automatic \
    --data-file=-
```

The application configuration uses Secret Manager **version names**, such as
`projects/my-project/secrets/truster-signing-key/versions/latest`.

## Usage

The typed `truster_config` value models the [Truster v3 application configuration](https://truster.dev/docs/config/) so type and supported cross-field errors fail during planning. Omit optional application settings to use Truster's own defaults. The module overrides `issuer_url`, `http_listen_addr`, and `secrets.provider`; the provider is always `google-secret-manager`. The `$schema` editor hint and `serving_certificate` are deployment-owned and intentionally omitted: generated configuration is served through Caddy, which owns TLS. The module also supplies the deployment's SQLite state path when `state_database` or its SQLite `path` is omitted. An explicit PostgreSQL state database is preserved. By default, the module grants the instance service account access only to runtime secrets referenced by the configuration.

By default, the migration-only
`state_database.migrations.connection_string_secret` is not granted to the
instance service account. Set `run_db_migrations = true` to grant
access to that secret and run `truster migrate` before every service start. A
failed migration prevents Truster from starting. Because migration
credentials usually have broader database permissions than runtime credentials,
keep the default and run migrations with a separate deployment identity in
stricter environments. See the
[state database guide](https://truster.dev/docs/state-database/).

```hcl
provider "google" {
  project = "my-project"
  region  = "us-central1"
  zone    = "us-central1-a"
}

locals {
  oidc_hostname = "auth.example.com"
}

resource "google_compute_network" "main" {
  name                    = "truster"
  auto_create_subnetworks = false
}

module "truster" {
  source = "truster/truster/google"

  network   = google_compute_network.main.self_link
  oidc_addr = local.oidc_hostname

  truster_config = {
    secrets = {
      signing_key_name    = "projects/my-project/secrets/truster-signing-key/versions/latest"
      encryption_key_name = "projects/my-project/secrets/truster-encryption-key/versions/latest"
    }
    user_login_connectors = {
      google = {
        type               = "google"
        display_name       = "Google"
        credentials_secret = "projects/my-project/secrets/truster-google/versions/latest"
      }
    }
    static_policy = {
      user_group_mappings = {
        prod-groups = {
          "alice@example.com" = ["prod-admins", "devs"]
        }
      }
      clients = {
        kubelogin-prod = {
          redirect_uris      = ["http://localhost:8000"]
          user_group_mapping = "prod-groups"
        }
        kubelogin-dev = {
          redirect_uris = ["http://localhost:18000"]
        }
      }
    }
  }
}

data "google_dns_managed_zone" "main" {
  name = "example-com"
}

resource "google_dns_record_set" "oidc_a" {
  count = module.truster.public_ipv4 != null ? 1 : 0

  managed_zone = data.google_dns_managed_zone.main.name
  name         = "${local.oidc_hostname}."
  type         = "A"
  ttl          = 300
  rrdatas      = [module.truster.public_ipv4]
}

resource "google_dns_record_set" "oidc_aaaa" {
  count = module.truster.public_ipv6 != null ? 1 : 0

  managed_zone = data.google_dns_managed_zone.main.name
  name         = "${local.oidc_hostname}."
  type         = "AAAA"
  ttl          = 300
  rrdatas      = [module.truster.public_ipv6]
}
```

Initialize and inspect the plan without applying infrastructure:

```bash
tofu init
tofu plan
```

When `subnetwork` is omitted, the module creates one. When using an existing subnetwork with `enable_ipv6 = true`, it must support external IPv6.

For an existing subnetwork:

```hcl
module "truster" {
  source = "truster/truster/google"

  # Other required inputs omitted.
  network    = google_compute_network.main.self_link
  subnetwork = google_compute_subnetwork.public.self_link
}
```

For an IPv4-only deployment:

```hcl
module "truster" {
  source = "truster/truster/google"

  # Other required inputs omitted.
  network     = google_compute_network.main.self_link
  enable_ipv6 = false
}
```

## Kubernetes integration

Configure the API server with the module's issuer and a key from `truster_config.static_policy.clients` (or a client ID managed by `policy_database`):

```bash
--oidc-issuer-url=https://auth.example.com
--oidc-client-id=kubelogin-prod
--oidc-username-claim=email
--oidc-groups-claim=groups
```

For example, use [kubelogin](https://github.com/int128/kubelogin) with PKCE:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-pkce-method=S256
```

## Variables

This table is the complete module input reference.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `name_prefix` | Prefix for resource names | `string` | `"truster"` | no |
| `labels` | Additional labels on supported resources | `map(string)` | `{}` | no |
| `project_id` | Google Cloud project ID; provider project when omitted | `string` | `null` | no |
| `region` | Google Cloud region; provider region when omitted | `string` | `null` | no |
| `zone` | Google Cloud zone; provider zone when omitted | `string` | `null` | no |
| `network` | VPC network name, self-link, or ID | `string` | — | yes |
| `subnetwork` | Subnetwork name, self-link, or ID; one is created when omitted | `string` | `null` | no |
| `subnetwork_cidr` | IPv4 CIDR for the created subnetwork | `string` | `"10.0.0.0/24"` | no |
| `oidc_addr` | Public OIDC server address, optionally including a port | `string` | — | yes |
| `truster_config` | Typed Truster v3 configuration object; deployment-owned fields are overridden | `object` | — | yes |
| `run_db_migrations` | Run migrations before every service start and grant access to the configured migration secret | `bool` | `false` | no |
| `enable_ipv4` | Enable a public IPv4 address | `bool` | `true` | no |
| `enable_ipv6` | Enable a public IPv6 address | `bool` | `true` | no |
| `machine_type` | Compute Engine machine type | `string` | `"e2-micro"` | no |
| `instance_disk_size_gb` | Instance boot disk size in GB | `number` | `10` | no |
| `boot_disk_type` | Boot disk type | `string` | `"pd-balanced"` | no |
| `boot_disk_kms_key_self_link` | Cloud KMS key self-link for boot disk encryption | `string` | `null` | no |
| `allowed_cidrs_ipv4` | IPv4 CIDRs allowed HTTP/HTTPS access | `list(string)` | `["0.0.0.0/0"]` | no |
| `allowed_cidrs_ipv6` | IPv6 CIDRs allowed HTTP/HTTPS access | `list(string)` | `["::/0"]` | no |
| `truster_version` | Truster release; must be `v2.0.0` or later, or `latest` | `string` | `"latest"` | no |
| `caddy_version` | Caddy version (`latest` uses the installer default) | `string` | `"latest"` | no |
| `service_account_email` | Existing instance service-account email; one is created when omitted | `string` | `null` | no |
| `grant_secret_accessor` | Grant the instance service account access to each Secret Manager secret referenced by `truster_config` | `bool` | `true` | no |
| `ssh_keys` | GCE metadata-format SSH public keys; empty disables SSH access | `list(string)` | `[]` | no |
| `ssh_allowed_cidrs_ipv4` | IPv4 CIDRs allowed SSH access when `ssh_keys` is non-empty | `list(string)` | `[]` | no |
| `ssh_allowed_cidrs_ipv6` | IPv6 CIDRs allowed SSH access when `ssh_keys` is non-empty | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `issuer_url` | OIDC issuer URL |
| `client_ids` | Keys from `truster_config.static_policy.clients`; empty for policy-database-only clients |
| `enable_ipv4` | Whether IPv4 is enabled |
| `enable_ipv6` | Whether IPv6 is enabled |
| `public_ipv4` | Public IPv4 address, or `null` |
| `public_ipv6` | Public IPv6 address, or `null` |
| `instance_id` | Compute Engine instance ID |
| `instance_name` | Compute Engine instance name |
| `subnetwork` | Subnetwork used by the instance |
| `service_account_email` | Instance service-account email |
| `instance_arch` | Detected instance architecture |
| `truster_version` | Resolved Truster version |
| `caddy_version` | Resolved Caddy version |

## License

Truster is licensed under the Apache License, Version 2.0.
Copyright The Truster Authors.
See the [LICENSE](./LICENSE) file for details.
