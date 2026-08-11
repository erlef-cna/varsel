# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/varsel start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :varsel, VarselWeb.Endpoint, server: true
end

config :varsel, VarselWeb.Endpoint, http: [port: String.to_integer(System.get_env("PORT", "4000"))]

# Test deployment flag: when true (the default), the instance serves a
# disallow-everything robots.txt, sends an `X-Robots-Tag` header blocking all
# indexing/link-following, and shows a warning banner on the home page. Set
# `TEST_DEPLOYMENT=false` on the real production instance to disable this.
with {:ok, value} <- System.fetch_env("TEST_DEPLOYMENT") do
  config :varsel, :test_deployment?, value in ~w(true 1)
end

# Reads one OAuth login provider's credentials under a common prefix. Returns
# `[]` when neither is set (provider disabled) and raises when only one is — a
# half-configured provider is an error, not an opt-out. `optional` carries
# settings that have a working default, so they neither enable the provider
# on their own nor are missed when it is enabled.
oauth_provider_config = fn prefix, optional ->
  credentials = [client_id: "CLIENT_ID", client_secret: "CLIENT_SECRET"]

  values =
    Enum.map(credentials, fn {key, var} -> {key, var, System.get_env("#{prefix}_#{var}")} end)

  extras =
    Enum.map(optional, fn {key, {var, default}} ->
      {key, System.get_env("#{prefix}_#{var}", default)}
    end)

  case Enum.split_with(values, fn {_key, _var, value} -> is_nil(value) end) do
    {_missing, []} ->
      []

    {[], set} ->
      Enum.map(set, fn {key, _var, value} -> {key, value} end) ++ extras

    {missing, _set} ->
      raise """
      Incomplete OAuth configuration for #{prefix}.

      Set both of #{Enum.map_join(credentials, ", ", fn {_key, var} -> "#{prefix}_#{var}" end)}, or
      neither to disable the provider. Missing: \
      #{Enum.map_join(missing, ", ", fn {_key, var, _value} -> "#{prefix}_#{var}" end)}
      """
  end
end

if config_env() != :test do
  # MITRE credentials are opt-in in development: with none of the variables
  # set, a built-in mock (`Varsel.Dev.MitreCveApiMock`) stands in for the MITRE
  # API so the app runs without credentials. Partial configuration is a mistake
  # rather than a choice, so it raises. Production always requires the real API.
  mitre_vars = ~w(MITRE_CVE_API_BASE_URL MITRE_CVE_API_ORG MITRE_CVE_API_USER MITRE_CVE_API_KEY)
  mitre_env = Map.new(mitre_vars, &{&1, System.get_env(&1)})
  mitre_missing = Enum.filter(mitre_vars, &is_nil(mitre_env[&1]))

  # "From" address for CNA notification emails (e.g. new vulnerability reports).
  config :varsel,
         :cna_email_from,
         System.get_env("CNA_EMAIL_FROM", "cna@erlef.org")

  # OAuth login providers are opt-in: a provider is only offered when every one
  # of its variables is set. Partial configuration is a mistake rather than a
  # choice, so it raises instead of silently disabling the provider. With none
  # set, local development falls back to the mock login. The callback URI is
  # not among them — `Varsel.Secrets` builds it from the endpoint.
  config :varsel, :github, oauth_provider_config.("GITHUB", [])

  # Hex.pm is self-hostable, so the base URL can be pointed at a local hexpm
  # for development; it defaults to the public one.
  config :varsel, :hex, oauth_provider_config.("HEX", base_url: {"BASE_URL", "https://hex.pm"})

  # hex.pm's report intake. The key set is pinned rather than fetched, so
  # verification never waits on hex.pm and rotation is a deliberate change.
  config :varsel, :hex_intake, jwks: System.get_env("HEX_INTAKE_JWKS")

  case {length(mitre_missing), config_env()} do
    {0, _env} ->
      config :varsel,
        mitre_cve_api: [
          base_url: mitre_env["MITRE_CVE_API_BASE_URL"],
          org: mitre_env["MITRE_CVE_API_ORG"],
          user: mitre_env["MITRE_CVE_API_USER"],
          api_key: mitre_env["MITRE_CVE_API_KEY"]
        ]

    {4, :dev} ->
      config :varsel,
        mitre_cve_api: [
          base_url: "http://mitre.invalid",
          org: "EEF",
          user: "mock@localhost",
          api_key: "mock",
          plug: Varsel.Dev.MitreCveApiMock
        ]

    {_missing_count, env} ->
      raise """
      Incomplete MITRE CVE API configuration.

      Set all of #{Enum.join(mitre_vars, ", ")}\
      #{if env == :dev, do: ",\nor none to use the built-in mock", else: ""}.
      Missing: #{Enum.join(mitre_missing, ", ")}
      """
  end
end

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  smtp_relay_host =
    System.get_env("SMTP_RELAY_HOST") ||
      raise("Missing environment variable `SMTP_RELAY_HOST`!")

  # gen_smtp sets `cacerts` as `:undefined`, which `ssl` rejects outright
  # when combined with `verify: :verify_peer`. Pass verification options
  # explicitly.
  # `:https` hostname matching is required for the wildcard certificates mail
  # relays typically serve (e.g. `*.fastmail.com` for `smtp.fastmail.com`),
  # which the default match function rejects.
  smtp_tls_options = [
    verify: :verify_peer,
    cacerts: :public_key.cacerts_get(),
    server_name_indication: String.to_charlist(smtp_relay_host),
    depth: 3,
    customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
  ]

  # Deliver mail over SMTP in production (adapter needs :gen_smtp).
  config :varsel, Varsel.Mailer,
    adapter: Swoosh.Adapters.SMTP,
    relay: smtp_relay_host,
    ssl: true,
    auth: :always,
    port: String.to_integer(System.get_env("SMTP_PORT") || "465"),
    retries: 2,
    no_mx_lookups: false,
    # Implicit TLS (port 465) connects via `smtp_socket:connect(ssl, ...)`,
    # which reads `:sockopts`; `:tls_options` is only consulted for the
    # STARTTLS upgrade. Set both so either relay style is verified.
    sockopts: smtp_tls_options,
    tls_options: smtp_tls_options,
    username:
      System.get_env("SMTP_USER") ||
        raise("Missing environment variable `SMTP_USER`!"),
    password:
      System.get_env("SMTP_PASSWORD") ||
        raise("Missing environment variable `SMTP_PASSWORD`!")

  config :varsel, Varsel.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # For machines with several cores, consider starting multiple pools of `pool_size`
    # pool_count: 4,
    socket_options: maybe_ipv6

  config :varsel, Varsel.Vault,
    ciphers: [
      default:
        {Cloak.Ciphers.AES.GCM,
         tag: "AES.GCM.V1",
         key:
           Base.decode64!(
             System.get_env("CLOAK_KEY") ||
               raise("Missing environment variable `CLOAK_KEY`!")
           )}
    ]

  config :varsel, VarselWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  config :varsel, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :varsel,
    oauth2_issuer_url: "https://#{host}",
    # Audience of minted access tokens and the protected-resource identity
    # (RFC 8707): the bare host, covering every token-consuming surface
    # (/mcp, /gql); scopes, not audiences, separate the surfaces.
    oauth2_resource_url: "https://#{host}",
    oauth2_signing_secret:
      System.get_env("OAUTH2_SIGNING_SECRET") ||
        raise("Missing environment variable `OAUTH2_SIGNING_SECRET`!")

  config :varsel,
    token_signing_secret:
      System.get_env("TOKEN_SIGNING_SECRET") ||
        raise("Missing environment variable `TOKEN_SIGNING_SECRET`!")
end
