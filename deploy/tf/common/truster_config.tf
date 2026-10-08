# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

variable "truster_config" {
  description = "Typed Truster v3 application configuration. The module injects deployment-owned settings."
  type = object({
    signing_algorithm = optional(string)
    jwks_kid          = optional(string)
    access_token_ttl  = optional(string)
    id_token_ttl      = optional(string)
    templates_dir     = optional(string)
    secrets = object({
      signing_key_name    = string
      encryption_key_name = optional(string)
    })
    user_login_connectors = map(object({
      type               = string
      display_name       = string
      order              = optional(number)
      credentials_secret = optional(string)
      scopes             = optional(list(string))
      google = optional(object({
        hd = optional(string)
      }))
      github = optional(object({
        hostname = optional(string)
      }))
      generic = optional(object({
        authorization_url    = string
        token_url            = string
        userinfo_url         = string
        email_field          = optional(string)
        email_verified_field = optional(string)
        subject_field        = optional(string)
        refresh = optional(object({
          scopes               = optional(list(string))
          authorization_params = optional(map(string))
        }))
      }))
    }))
    email = optional(object({
      verification_mode = optional(string)
      otp_secret_name   = optional(string)
      otp_ttl           = optional(string)
      smtp = optional(object({
        host               = string
        port               = number
        from_name          = optional(string)
        from_address       = string
        credentials_secret = optional(string)
        tls_mode           = optional(string)
      }))
      turnstile = optional(object({
        site_key    = string
        secret_name = string
      }))
    }))
    service_token_issuers = optional(map(object({
      provider      = string
      issuer_url    = optional(string)
      signing_algs  = optional(list(string))
      max_token_age = optional(string)
    })))
    static_policy = optional(object({
      require_user_groups_from_policy = optional(bool)
      default_redirect_uris           = optional(list(string))
      user_group_mappings             = optional(map(map(list(string))))
      trust_policies = optional(map(object({
        issuer          = string
        subject         = optional(string)
        groups          = optional(list(string))
        required_claims = optional(any)
        claims          = optional(any)
      })))
      clients = optional(map(object({
        redirect_uris                   = optional(list(string))
        user_group_mapping              = optional(string)
        require_user_groups_from_policy = optional(bool)
        dpop = optional(object({
          mode              = optional(string)
          signing_algorithm = optional(string)
        }))
        require_par = optional(bool)
        trust_bindings = optional(list(object({
          id           = string
          trust_policy = string
          subject      = optional(string)
          groups       = optional(list(string))
          claims       = optional(any)
        })))
        refresh_tokens = optional(object({
          enabled              = optional(bool)
          allow_offline_access = optional(bool)
          session_idle_ttl     = optional(string)
          session_absolute_ttl = optional(string)
          offline_idle_ttl     = optional(string)
          offline_absolute_ttl = optional(string)
        }))
      })))
    }))
    state_database = optional(object({
      driver                   = optional(string)
      path                     = optional(string)
      connection_string_secret = optional(string)
      max_connections          = optional(number)
      query_timeout            = optional(string)
      migrations = optional(object({
        connection_string_secret = string
      }))
    }))
    policy_database = optional(object({
      driver                   = string
      connection_string_secret = string
      redirect_uris            = list(string)
      client_defaults = optional(object({
        require_user_groups_from_policy = optional(bool)
        dpop = optional(object({
          mode              = optional(string)
          signing_algorithm = optional(string)
        }))
        require_par = optional(bool)
        refresh_tokens = optional(object({
          enabled              = optional(bool)
          allow_offline_access = optional(bool)
          session_idle_ttl     = optional(string)
          session_absolute_ttl = optional(string)
          offline_idle_ttl     = optional(string)
          offline_absolute_ttl = optional(string)
        }))
      }))
      queries = optional(map(string))
      client_lookup_cache = optional(object({
        ttl          = optional(string)
        negative_ttl = optional(string)
        max_entries  = optional(number)
      }))
      policy_build_cache = optional(object({
        max_entries = optional(number)
      }))
      query_timeout   = optional(string)
      max_connections = optional(number)
      max_trust_rows  = optional(number)
      max_groups      = optional(number)
      max_group_bytes = optional(number)
      max_json_bytes  = optional(number)
    }))
  })

  validation {
    condition     = var.truster_config.signing_algorithm == null ? true : contains(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"], var.truster_config.signing_algorithm)
    error_message = "truster_config.signing_algorithm must be supported by Truster."
  }

  validation {
    condition     = trimspace(var.truster_config.secrets.signing_key_name) != "" && length(var.truster_config.user_login_connectors) > 0
    error_message = "truster_config must define a signing key and at least one user login connector."
  }

  validation {
    condition = alltrue([
      for id, connector in var.truster_config.user_login_connectors :
      can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", id)) &&
      contains(["google", "github", "generic", "email"], connector.type) &&
      trimspace(connector.display_name) != "" &&
      (connector.type == "email" || try(trimspace(connector.credentials_secret) != "", false)) &&
      (connector.type == "email" ? (
        connector.credentials_secret == null && connector.scopes == null && connector.google == null && connector.github == null && connector.generic == null
        ) : connector.type == "google" ? (
        connector.github == null && connector.generic == null &&
        alltrue([for scope in coalesce(connector.scopes, []) : trimspace(scope) != ""])
        ) : connector.type == "github" ? (
        connector.google == null && connector.generic == null &&
        alltrue([for scope in coalesce(connector.scopes, []) : trimspace(scope) != ""])
        ) : connector.type == "generic" ? (
        connector.google == null && connector.github == null && connector.generic != null &&
        try(trimspace(connector.generic.authorization_url) != "", false) &&
        try(trimspace(connector.generic.token_url) != "", false) &&
        try(trimspace(connector.generic.userinfo_url) != "", false) &&
        alltrue([for scope in coalesce(connector.scopes, []) : trimspace(scope) != ""]) &&
        alltrue([for scope in coalesce(try(connector.generic.refresh.scopes, null), []) : trimspace(scope) != "" && !can(regex("\\s", scope))]) &&
        alltrue([for key in keys(coalesce(try(connector.generic.refresh.authorization_params, null), {})) : trimspace(key) != "" && !contains(["client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"], key)])
      ) : false)
    ])
    error_message = "Each connector must have a path-safe ID, display name, and only the credentials, scopes, and provider block valid for its type; generic endpoints and refresh values must be nonblank and refresh authorization_params cannot override Truster-owned parameters."
  }

  validation {
    condition = !(
      contains([for connector in values(var.truster_config.user_login_connectors) : connector.type], "github") ||
      (contains([for connector in values(var.truster_config.user_login_connectors) : connector.type != "email"], true) && (
        contains([for client in values(coalesce(try(var.truster_config.static_policy.clients, null), {})) : try(coalesce(client.refresh_tokens.enabled, false), false)], true) ||
        try(coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.enabled, false), false)
      ))
    ) || try(trimspace(var.truster_config.secrets.encryption_key_name) != "", false)
    error_message = "truster_config.secrets.encryption_key_name is required for GitHub and for enabled refresh tokens used with a non-email connector."
  }

  validation {
    condition     = try(var.truster_config.email.verification_mode, null) == null ? true : contains(["disabled", "provider", "strict"], var.truster_config.email.verification_mode)
    error_message = "truster_config.email.verification_mode must be disabled, provider, or strict."
  }

  validation {
    condition     = try(var.truster_config.email.smtp.tls_mode, null) == null ? true : contains(["starttls", "implicit", "plaintext"], var.truster_config.email.smtp.tls_mode)
    error_message = "truster_config.email.smtp.tls_mode must be starttls, implicit, or plaintext."
  }

  validation {
    condition = !(
      contains([for connector in values(var.truster_config.user_login_connectors) : connector.type], "email") ||
      contains(["provider", "strict"], coalesce(try(var.truster_config.email.verification_mode, null), "disabled"))
      ) || (
      var.truster_config.email != null &&
      try(trimspace(var.truster_config.email.otp_secret_name) != "", false) &&
      try(var.truster_config.email.smtp != null, false) &&
      try(contains([for minutes in range(1, 11) : timeadd("2000-01-01T00:00:00Z", "${minutes}m")], timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.email.otp_ttl, "5m"))), false)
    )
    error_message = "An email connector or provider/strict verification requires email configuration, a nonblank otp_secret_name, complete SMTP configuration, and otp_ttl equivalent to 1-10 whole minutes."
  }

  validation {
    condition = var.truster_config.email == null ? true : (
      var.truster_config.email.smtp == null ? true : (
        trimspace(var.truster_config.email.smtp.host) != "" &&
        trimspace(var.truster_config.email.smtp.from_address) != "" &&
        can(regex("^[^@\\s<>]+@[^@\\s<>]+$", var.truster_config.email.smtp.from_address)) &&
        (coalesce(var.truster_config.email.smtp.tls_mode, "starttls") != "plaintext" || var.truster_config.email.smtp.host == "localhost")
      )
    )
    error_message = "email.smtp requires a nonblank host and bare, basic-valid from_address; plaintext TLS mode is only permitted with host localhost."
  }

  validation {
    condition     = try(length(var.truster_config.static_policy.clients) > 0, false) ? true : var.truster_config.policy_database != null
    error_message = "truster_config must configure static_policy.clients or policy_database."
  }

  validation {
    condition     = try(var.truster_config.static_policy.default_redirect_uris, null) == null ? true : length(var.truster_config.static_policy.default_redirect_uris) > 0
    error_message = "static_policy.default_redirect_uris must be omitted or nonempty."
  }

  validation {
    condition = alltrue([
      for client in values(coalesce(try(var.truster_config.static_policy.clients, null), {})) :
      try(length(client.redirect_uris) > 0, false) || try(length(var.truster_config.static_policy.default_redirect_uris) > 0, false)
    ])
    error_message = "Every static client requires nonempty redirect_uris or nonempty static_policy.default_redirect_uris."
  }

  validation {
    condition = var.truster_config.state_database == null ? true : (
      coalesce(var.truster_config.state_database.driver, "sqlite") == "sqlite" ? (
        var.truster_config.state_database.connection_string_secret == null &&
        var.truster_config.state_database.max_connections == null &&
        var.truster_config.state_database.query_timeout == null &&
        var.truster_config.state_database.migrations == null
        ) : coalesce(var.truster_config.state_database.driver, "") == "postgresql" ? (
        var.truster_config.state_database.path == null &&
        try(trimspace(var.truster_config.state_database.connection_string_secret) != "", false)
      ) : false
    )
    error_message = "state_database must contain only SQLite fields or only PostgreSQL fields, and PostgreSQL requires connection_string_secret."
  }

  validation {
    condition = var.truster_config.policy_database == null ? true : (
      var.truster_config.policy_database.driver == "postgresql" &&
      trimspace(var.truster_config.policy_database.connection_string_secret) != "" &&
      length(var.truster_config.policy_database.redirect_uris) > 0
    )
    error_message = "truster_config.policy_database requires the postgresql driver, a connection string secret, and at least one redirect URI."
  }

  validation {
    condition = alltrue([
      for key, sql in coalesce(try(var.truster_config.policy_database.queries, null), {}) :
      contains(["client_exists", "user_access", "trust_issuer", "trust_bindings"], key) &&
      (sql == null ? true : trimspace(sql) != "")
    ])
    error_message = "policy_database.queries supports only client_exists, user_access, trust_issuer, and trust_bindings; values must be null or nonblank SQL."
  }

  validation {
    condition = alltrue(concat(
      [for client in values(coalesce(try(var.truster_config.static_policy.clients, null), {})) :
        client.dpop == null ? true : (
          contains(["disabled", "required"], coalesce(client.dpop.mode, "disabled")) &&
          (client.dpop.signing_algorithm == null ? true : (coalesce(client.dpop.mode, "disabled") == "required" && contains(["ES256", "ES512"], client.dpop.signing_algorithm)))
        )
      ],
      [try(var.truster_config.policy_database.client_defaults.dpop, null) == null ? true : (
        contains(["disabled", "required"], coalesce(var.truster_config.policy_database.client_defaults.dpop.mode, "disabled")) &&
        (var.truster_config.policy_database.client_defaults.dpop.signing_algorithm == null ? true : (coalesce(var.truster_config.policy_database.client_defaults.dpop.mode, "disabled") == "required" && contains(["ES256", "ES512"], var.truster_config.policy_database.client_defaults.dpop.signing_algorithm)))
      )]
    ))
    error_message = "DPoP mode must be disabled or required; signing_algorithm requires required mode and must be ES256 or ES512."
  }

  validation {
    condition = alltrue([
      for issuer in values(coalesce(var.truster_config.service_token_issuers, {})) :
      contains(["github", "buildkite", "oidc"], issuer.provider) && (
        issuer.provider == "oidc" ? (
          try(trimspace(issuer.issuer_url) != "", false) &&
          try(length(issuer.signing_algs) > 0, false) &&
          alltrue([for alg in coalesce(issuer.signing_algs, []) : contains(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"], alg)]) &&
          try(trimspace(issuer.max_token_age) != "", false)
          ) : (
          issuer.issuer_url == null && issuer.signing_algs == null && issuer.max_token_age == null
        )
      )
    ])
    error_message = "Service token issuers must use github, buildkite, or oidc; presets cannot override issuer fields, while oidc requires issuer_url, supported signing_algs, and max_token_age."
  }

  validation {
    condition = alltrue(concat(
      [for refresh in [for client in values(coalesce(try(var.truster_config.static_policy.clients, null), {})) : client.refresh_tokens if client.refresh_tokens != null] :
        (!coalesce(refresh.allow_offline_access, false) || coalesce(refresh.enabled, false)) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(refresh.session_idle_ttl, "30m")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(refresh.session_absolute_ttl, "10h")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(refresh.offline_idle_ttl, "720h")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(refresh.offline_absolute_ttl, "2160h")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(refresh.session_idle_ttl, "30m")), timeadd("2000-01-01T00:00:00Z", coalesce(refresh.session_absolute_ttl, "10h"))) <= 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(refresh.offline_idle_ttl, "720h")), timeadd("2000-01-01T00:00:00Z", coalesce(refresh.offline_absolute_ttl, "2160h"))) <= 0, false)
      ],
      [try(var.truster_config.policy_database.client_defaults.refresh_tokens, null) == null ? true : (
        (!coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.allow_offline_access, false) || coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.enabled, false)) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.session_idle_ttl, "30m")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.session_absolute_ttl, "10h")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.offline_idle_ttl, "720h")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.offline_absolute_ttl, "2160h")), "2000-01-01T00:00:00Z") > 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.session_idle_ttl, "30m")), timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.session_absolute_ttl, "10h"))) <= 0, false) &&
        try(timecmp(timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.offline_idle_ttl, "720h")), timeadd("2000-01-01T00:00:00Z", coalesce(var.truster_config.policy_database.client_defaults.refresh_tokens.offline_absolute_ttl, "2160h"))) <= 0, false)
      )]
    ))
    error_message = "Refresh durations must be positive, allow_offline_access requires enabled, and session/offline idle TTLs must not exceed their absolute TTLs."
  }

  validation {
    condition = alltrue(concat(
      [for connector in values(var.truster_config.user_login_connectors) : connector.order == null ? true : floor(connector.order) == connector.order],
      [try(var.truster_config.email.smtp.port, null) == null ? true : (floor(var.truster_config.email.smtp.port) == var.truster_config.email.smtp.port && var.truster_config.email.smtp.port >= 1 && var.truster_config.email.smtp.port <= 65535)],
      [try(var.truster_config.state_database.max_connections, null) == null ? true : (floor(var.truster_config.state_database.max_connections) == var.truster_config.state_database.max_connections && var.truster_config.state_database.max_connections >= 1)],
      [try(var.truster_config.policy_database.max_connections, null) == null ? true : (floor(var.truster_config.policy_database.max_connections) == var.truster_config.policy_database.max_connections && var.truster_config.policy_database.max_connections >= 1 && var.truster_config.policy_database.max_connections <= 32)],
      [for value in [
        try(var.truster_config.policy_database.client_lookup_cache.max_entries, null),
        try(var.truster_config.policy_database.policy_build_cache.max_entries, null),
      ] : floor(value) == value && value >= 1 && value <= 100000 if value != null],
      [for value in [
        try(var.truster_config.policy_database.max_trust_rows, null),
        try(var.truster_config.policy_database.max_groups, null),
      ] : floor(value) == value && value >= 1 && value <= 1000 if value != null],
      [try(var.truster_config.policy_database.max_group_bytes, null) == null ? true : (floor(var.truster_config.policy_database.max_group_bytes) == var.truster_config.policy_database.max_group_bytes && var.truster_config.policy_database.max_group_bytes >= 1 && var.truster_config.policy_database.max_group_bytes <= 4096)],
      [try(var.truster_config.policy_database.max_json_bytes, null) == null ? true : (floor(var.truster_config.policy_database.max_json_bytes) == var.truster_config.policy_database.max_json_bytes && var.truster_config.policy_database.max_json_bytes >= 1024 && var.truster_config.policy_database.max_json_bytes <= 1048576)]
    ))
    error_message = "Integer configuration fields must use whole numbers within the bounds supported by Truster."
  }

}
