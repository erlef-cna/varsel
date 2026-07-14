# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

import Config

config :ash, policies: [show_policy_breakdowns?: true], disable_async?: true

config :bcrypt_elixir, log_rounds: 1

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

config :varsel, Oban, testing: :manual

# In test we don't send emails
config :varsel, Varsel.Mailer, adapter: Swoosh.Adapters.Test

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :varsel, Varsel.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "varsel_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

config :varsel, Varsel.Vault,
  ciphers: [
    default:
      {Cloak.Ciphers.AES.GCM, tag: "AES.GCM.V1", key: Base.decode64!("q69rFPGIqHZTHBNhGOKNZRpORMoGBiGDLKBpKpfMWQo=")}
  ]

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :varsel, VarselWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "jdkXkwkaDUSqRpTF7YCN23q+0nRXBt17mEoKtX93dp8D/gmeUcpyZ3Vp0z9rLsmr",
  server: false

config :varsel, :cna_email_from, "cna@erlef.org"

config :varsel,
  token_signing_secret: "6efZN/F7dwuoM9KP4oUWol4pbbSwNQ8J",
  cvelint_bin: System.get_env("CVELINT_BIN", "cvelint"),
  hex_core: %{http_adapter: {Varsel.Test.HexHTTPStub, %{}}},
  cwe_catalog: [plug: {Req.Test, Varsel.CWE.Weakness}],
  capec_catalog: [plug: {Req.Test, Varsel.CAPEC.AttackPattern}],
  mitre_cve_api: [
    base_url: "https://cveawg-test.mitre.org/api",
    org: "test-org",
    user: "test-user@example.com",
    api_key: "test-api-key",
    plug: {Req.Test, Varsel.CVE.MitreCveApi}
  ]
