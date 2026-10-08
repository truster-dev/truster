mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-1a"] }
  }

  mock_data "aws_vpc" {
    defaults = {
      cidr_block = "10.0.0.0/16"
      ipv6_cidr_block_associations = [{
        association_id         = "vpc-cidr-assoc-0123456789abcdef0"
        ip_source              = "amazon"
        ipv6_address_attribute = "public"
        ipv6_cidr_block        = "2001:db8::/56"
        ipv6_pool              = "Amazon"
        network_border_group   = "us-east-1"
        state                  = "associated"
      }]
      region = "us-east-1"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = { supported_architectures = ["arm64"] }
  }

  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }

  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }

  mock_resource "aws_launch_template" {
    defaults = { id = "lt-0123456789abcdef0" }
  }

  mock_resource "aws_network_interface" {
    defaults = { ipv6_addresses = ["2001:db8::10"] }
  }
}

mock_provider "http" {
  mock_data "http" {
    defaults = { response_body = "#!/bin/bash\n" }
  }
}

variables {
  vpc_id          = "vpc-0123456789abcdef0"
  subnet_id       = "subnet-0123456789abcdef0"
  oidc_addr       = "auth.example.com"
  truster_version = "v2.0.0"
  caddy_version   = "v2.10.0"

  truster_config = {
    secrets = {
      signing_key_name    = "/truster/signing"
      encryption_key_name = "/truster/encryption"
    }
    user_login_connectors = {
      google = {
        type               = "google"
        display_name       = "Google"
        credentials_secret = "/truster/google"
      }
    }
    static_policy = {
      clients = {
        app = {
          redirect_uris = ["https://app.example/callback"]
        }
      }
    }
  }
}

run "valid_cross_field_configuration" {
  command = plan
}

run "policy_queries_omitted_use_defaults" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
      }
    }
  }

  assert {
    condition     = !contains(keys(jsondecode(local.config_jsonc).policy_database), "queries")
    error_message = "Omitted queries must remain absent so Truster uses built-in SQL."
  }
}

run "policy_queries_partial_overrides_preserve_sql" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
        queries = {
          client_exists = " SELECT 1 "
          trust_issuer  = "SELECT issuer FROM custom_issuer WHERE issuer = $1"
        }
      }
    }
  }

  assert {
    condition = jsondecode(local.config_jsonc).policy_database.queries == {
      client_exists = " SELECT 1 "
      trust_issuer  = "SELECT issuer FROM custom_issuer WHERE issuer = $1"
    }
    error_message = "Partial query overrides must preserve SQL, including trust_issuer, without adding omitted keys."
  }
}

run "policy_queries_null_disables_lookup" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
        queries = {
          client_exists  = null
          user_access    = null
          trust_issuer   = null
          trust_bindings = null
        }
      }
    }
  }

  assert {
    condition = jsondecode(local.config_jsonc).policy_database.queries == {
      client_exists  = null
      user_access    = null
      trust_issuer   = null
      trust_bindings = null
    }
    error_message = "Explicit null must survive serialization for each supported query."
  }
}

run "policy_queries_unknown_key_is_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
        queries                  = { unknown = "SELECT 1" }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "policy_queries_unknown_null_key_is_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
        queries                  = { unknown = null }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "policy_queries_empty_sql_is_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
        queries                  = { user_access = "" }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "policy_queries_whitespace_sql_is_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
        queries                  = { trust_issuer = " \t\n " }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "created_subnet_uses_associated_vpc_ipv6_cidr" {
  command = plan

  variables {
    subnet_id = null
  }

  assert {
    condition     = aws_subnet.main[0].ipv6_cidr_block == "2001:db8::/64"
    error_message = "An automatically created subnet must derive its IPv6 CIDR from the VPC's associated IPv6 CIDR."
  }
}

run "custom_oidc_port_reaches_caddy" {
  command = plan

  variables {
    oidc_addr = "auth.example.com:8443"
  }

  assert {
    condition     = output.issuer_url == "https://auth.example.com:8443"
    error_message = "The issuer URL must retain the custom OIDC port."
  }

  assert {
    condition     = strcontains(base64decode(aws_launch_template.main.user_data), "OIDC_ADDR=auth.example.com:8443")
    error_message = "Userdata must pass the custom OIDC port to Caddy."
  }
}

run "all_allowed_cidrs_create_ingress_rules" {
  command = plan

  variables {
    allowed_cidrs_ipv4 = ["192.0.2.0/24", "198.51.100.0/24"]
    allowed_cidrs_ipv6 = ["2001:db8::/48", "2001:db8:1::/48"]
  }

  assert {
    condition = (
      length(aws_vpc_security_group_ingress_rule.http_ipv4) == 2 &&
      length(aws_vpc_security_group_ingress_rule.https_ipv4) == 2 &&
      length(aws_vpc_security_group_ingress_rule.http_ipv6) == 2 &&
      length(aws_vpc_security_group_ingress_rule.https_ipv6) == 2
    )
    error_message = "Every allowed IPv4 and IPv6 CIDR must receive HTTP and HTTPS ingress rules."
  }
}

run "shared_instance_inputs_control_aws_resources" {
  command = plan

  variables {
    enable_ipv6            = false
    instance_disk_size_gb  = 20
    ssh_key_name           = "operator"
    ssh_allowed_cidrs_ipv4 = ["192.0.2.0/24"]
    ssh_allowed_cidrs_ipv6 = ["2001:db8::/48"]
  }

  assert {
    condition     = aws_network_interface.main.ipv6_address_count == 0
    error_message = "Disabling IPv6 must stop assignment of an IPv6 address."
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.ssh_ipv4) == 1
    error_message = "SSH rules must use the enabled IP families and dedicated SSH CIDRs."
  }

  assert {
    condition     = aws_launch_template.main.block_device_mappings[0].ebs[0].volume_size == 20
    error_message = "instance_disk_size_gb must set the EC2 root volume size."
  }

  assert {
    condition     = output.enable_ipv6 == false && output.public_ipv6 == null
    error_message = "Disabling IPv6 must be reflected in the module outputs."
  }
}

run "at_least_one_ip_family_is_required" {
  command = plan

  variables {
    enable_ipv4 = false
    enable_ipv6 = false
  }

  expect_failures = [aws_launch_template.main]
}

run "refresh_with_non_email_connector_requires_encryption" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = {
          type               = "google"
          display_name       = "Google"
          credentials_secret = "/truster/google"
        }
      }
      static_policy = {
        clients = {
          app = {
            redirect_uris  = ["https://app.example/callback"]
            refresh_tokens = { enabled = true }
          }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "email_delivery_requires_smtp" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        email = { type = "email", display_name = "Email" }
      }
      email         = { otp_secret_name = "/truster/otp", otp_ttl = "5m" }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }

  expect_failures = [var.truster_config]
}

run "static_client_requires_redirects" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      static_policy = { clients = { app = {} } }
    }
  }

  expect_failures = [var.truster_config]
}

run "generic_refresh_cannot_override_owned_parameters" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        upstream = {
          type               = "generic"
          display_name       = "Upstream"
          credentials_secret = "/truster/upstream"
          generic = {
            authorization_url = "https://idp.example/authorize"
            token_url         = "https://idp.example/token"
            userinfo_url      = "https://idp.example/userinfo"
            refresh           = { authorization_params = { client_id = "override" } }
          }
        }
      }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }

  expect_failures = [var.truster_config]
}

run "refresh_idle_ttl_cannot_exceed_absolute_ttl" {
  command = plan

  variables {
    truster_config = {
      secrets = {
        signing_key_name    = "/truster/signing"
        encryption_key_name = "/truster/encryption"
      }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      static_policy = {
        clients = {
          app = {
            redirect_uris = ["https://app.example/callback"]
            refresh_tokens = {
              enabled              = true
              session_idle_ttl     = "1h30m"
              session_absolute_ttl = "1h"
            }
          }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "preset_service_issuer_fields_cannot_be_overridden" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "/truster/google" }
      }
      service_token_issuers = {
        actions = { provider = "github", signing_algs = ["RS256"] }
      }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }

  expect_failures = [var.truster_config]
}

run "policy_database_empty_refresh_uses_disabled_default" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "[REDACTED:secret-value]" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "/truster/policy-database"
        redirect_uris            = ["https://app.example/callback"]
        client_defaults          = { refresh_tokens = {} }
      }
    }
  }
}

run "explicit_empty_default_redirects_are_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "[REDACTED:secret-value]" }
      }
      static_policy = {
        default_redirect_uris = []
        clients = {
          app = { redirect_uris = ["https://app.example/callback"] }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "zero_refresh_duration_is_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = {
        signing_key_name    = "/truster/signing"
        encryption_key_name = "/truster/encryption"
      }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "[REDACTED:secret-value]" }
      }
      static_policy = {
        clients = {
          app = {
            redirect_uris = ["https://app.example/callback"]
            refresh_tokens = {
              enabled          = true
              session_idle_ttl = "0s"
            }
          }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "equivalent_email_otp_duration_is_valid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "/truster/signing" }
      user_login_connectors = {
        email = { type = "email", display_name = "Email" }
      }
      email = {
        otp_secret_name = "/truster/otp"
        otp_ttl         = "60s"
        smtp = {
          host         = "smtp.example.com"
          port         = 587
          from_address = "auth@example.com"
        }
      }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }
}
