# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

locals {
  state_database_input  = try(var.truster_config.state_database, null)
  state_database_driver = try(coalesce(try(local.state_database_input.driver, null), "sqlite"), "sqlite")
  state_database = merge(
    local.state_database_input == null ? {} : {
      for key, value in local.state_database_input : key => value
      if value != null && key != "migrations"
    },
    try(local.state_database_input.migrations, null) == null ? {} : {
      migrations = {
        for key, value in local.state_database_input.migrations : key => value
        if value != null
      }
    },
    local.state_database_driver == "sqlite" ? {
      driver = "sqlite"
      path   = try(coalesce(try(local.state_database_input.path, null), "/var/lib/truster/truster-state.db"), "/var/lib/truster/truster-state.db")
    } : {}
  )

  user_login_connectors = {
    for id, connector in var.truster_config.user_login_connectors : id => merge(
      {
        for key, value in connector : key => value
        if value != null && !contains(["google", "github", "generic"], key)
      },
      connector.google == null ? {} : {
        google = { for key, value in connector.google : key => value if value != null }
      },
      connector.github == null ? {} : {
        github = { for key, value in connector.github : key => value if value != null }
      },
      connector.generic == null ? {} : {
        generic = merge(
          {
            for key, value in connector.generic : key => value
            if value != null && key != "refresh"
          },
          connector.generic.refresh == null ? {} : {
            refresh = { for key, value in connector.generic.refresh : key => value if value != null }
          }
        )
      }
    )
  }

  email = var.truster_config.email == null ? null : merge(
    {
      for key, value in var.truster_config.email : key => value
      if value != null && !contains(["smtp", "turnstile"], key)
    },
    var.truster_config.email.smtp == null ? {} : {
      smtp = { for key, value in var.truster_config.email.smtp : key => value if value != null }
    },
    var.truster_config.email.turnstile == null ? {} : {
      turnstile = { for key, value in var.truster_config.email.turnstile : key => value if value != null }
    }
  )

  service_token_issuers = var.truster_config.service_token_issuers == null ? null : {
    for id, issuer in var.truster_config.service_token_issuers : id => {
      for key, value in issuer : key => value if value != null
    }
  }

  static_policy = var.truster_config.static_policy == null ? null : merge(
    {
      for key, value in var.truster_config.static_policy : key => value
      if value != null && !contains(["trust_policies", "clients"], key)
    },
    var.truster_config.static_policy.trust_policies == null ? {} : {
      trust_policies = {
        for id, policy in var.truster_config.static_policy.trust_policies : id => {
          for key, value in policy : key => value if value != null
        }
      }
    },
    var.truster_config.static_policy.clients == null ? {} : {
      clients = {
        for id, client in var.truster_config.static_policy.clients : id => merge(
          {
            for key, value in client : key => value
            if value != null && !contains(["dpop", "trust_bindings", "refresh_tokens"], key)
          },
          client.dpop == null ? {} : {
            dpop = { for key, value in client.dpop : key => value if value != null }
          },
          client.trust_bindings == null ? {} : {
            trust_bindings = [
              for binding in client.trust_bindings : {
                for key, value in binding : key => value if value != null
              }
            ]
          },
          client.refresh_tokens == null ? {} : {
            refresh_tokens = { for key, value in client.refresh_tokens : key => value if value != null }
          }
        )
      }
    }
  )

  policy_database = var.truster_config.policy_database == null ? null : merge(
    {
      for key, value in var.truster_config.policy_database : key => value
      if value != null && !contains(["client_defaults", "queries", "client_lookup_cache", "policy_build_cache"], key)
    },
    var.truster_config.policy_database.client_defaults == null ? {} : {
      client_defaults = merge(
        {
          for key, value in var.truster_config.policy_database.client_defaults : key => value
          if value != null && !contains(["dpop", "refresh_tokens"], key)
        },
        var.truster_config.policy_database.client_defaults.dpop == null ? {} : {
          dpop = { for key, value in var.truster_config.policy_database.client_defaults.dpop : key => value if value != null }
        },
        var.truster_config.policy_database.client_defaults.refresh_tokens == null ? {} : {
          refresh_tokens = { for key, value in var.truster_config.policy_database.client_defaults.refresh_tokens : key => value if value != null }
        }
      )
    },
    var.truster_config.policy_database.queries == null ? {} : {
      queries = var.truster_config.policy_database.queries
    },
    var.truster_config.policy_database.client_lookup_cache == null ? {} : {
      client_lookup_cache = { for key, value in var.truster_config.policy_database.client_lookup_cache : key => value if value != null }
    },
    var.truster_config.policy_database.policy_build_cache == null ? {} : {
      policy_build_cache = { for key, value in var.truster_config.policy_database.policy_build_cache : key => value if value != null }
    }
  )

  application_config = merge(
    {
      for key, value in var.truster_config : key => value
      if value != null && !contains(["secrets", "user_login_connectors", "email", "service_token_issuers", "static_policy", "state_database", "policy_database"], key)
    },
    {
      secrets               = { for key, value in var.truster_config.secrets : key => value if value != null }
      user_login_connectors = local.user_login_connectors
      state_database        = local.state_database
    },
    local.email == null ? {} : { email = local.email },
    local.service_token_issuers == null ? {} : { service_token_issuers = local.service_token_issuers },
    local.static_policy == null ? {} : { static_policy = local.static_policy },
    local.policy_database == null ? {} : { policy_database = local.policy_database }
  )

  # Truster owns defaults for omitted application settings. The module only
  # injects values owned by this deployment.
}
