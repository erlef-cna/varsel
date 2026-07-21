# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
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

if config_env() != :test do
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

  # "From" address for CNA notification emails (e.g. new vulnerability reports).
  config :varsel,
         :cna_email_from,
         System.get_env("CNA_EMAIL_FROM", "cna@erlef.org")

  config :varsel,
    mitre_cve_api: [
      base_url:
        System.get_env("MITRE_CVE_API_BASE_URL") ||
          raise("Missing environment variable `MITRE_CVE_API_BASE_URL`!"),
      org:
        System.get_env("MITRE_CVE_API_ORG") ||
          raise("Missing environment variable `MITRE_CVE_API_ORG`!"),
      user:
        System.get_env("MITRE_CVE_API_USER") ||
          raise("Missing environment variable `MITRE_CVE_API_USER`!"),
      api_key:
        System.get_env("MITRE_CVE_API_KEY") ||
          raise("Missing environment variable `MITRE_CVE_API_KEY`!")
    ],
    github: [
      client_id:
        System.get_env("GITHUB_CLIENT_ID") ||
          raise("Missing environment variable `GITHUB_CLIENT_ID`!"),
      client_secret:
        System.get_env("GITHUB_CLIENT_SECRET") ||
          raise("Missing environment variable `GITHUB_CLIENT_SECRET`!"),
      redirect_uri:
        System.get_env("GITHUB_REDIRECT_URI") ||
          raise("Missing environment variable `GITHUB_REDIRECT_URI`!")
    ]
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

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :varsel, VarselWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :varsel, VarselWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.

  # Deliver mail over SMTP in production (adapter needs :gen_smtp).
  config :varsel, Varsel.Mailer,
    adapter: Swoosh.Adapters.SMTP,
    relay:
      System.get_env("SMTP_RELAY_HOST") ||
        raise("Missing environment variable `SMTP_RELAY_HOST`!"),
    ssl: true,
    auth: :always,
    port: String.to_integer(System.get_env("SMTP_PORT") || "465"),
    retries: 2,
    no_mx_lookups: false,
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
