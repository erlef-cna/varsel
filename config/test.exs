# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

import Config

config :ash, policies: [show_policy_breakdowns?: true], disable_async?: true

config :ash_authentication,
       :http_adapter,
       {Assent.HTTPAdapter.Req, plug: {Req.Test, Varsel.GitHub.UserToken}}

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
  hex_core: %{
    http_adapter: {Varsel.Test.HexHTTPStub, %{}},
    repo_verify: false,
    repo_verify_origin: false
  },
  github_api: [plug: {Req.Test, Varsel.GitHub.Client}],
  github: [
    client_id: "Ov23liTestApp",
    client_secret: "test-secret",
    app_id: "424242",
    # A throwaway key that signs the App's JWT in tests only.
    private_key: """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAt0H8ihX6iifyQJBJXim8DMJqhPbeTNfZz18DbWZQsg1GnQTs
    tNZAZGqA7UsFGG87CWEdCXGWFSq8XOncynE+5HV4DN8GDfHndNyqVedh8U2wj5qo
    FTWZ++nfJVDJbK4SPeVHSsFTGTrm6BLglUCAXtnRO9TXzNk3RhNQQZgI+LvqV9Cw
    Neirf/qTGMllqI+JROjdQ0wOlmvEWXytq3L/3+7uv6hdIvGgtLWOZGgJBSF0KIpf
    EJfpfG5yUuKO5LygxfO857fOfRgZZxJf6jm6qFIBznAfNuYFDabpBz7EzHWChXf3
    tu2UHeEBWw9k2TBXlyvcFZ/y5jKYfO2O/AH2CwIDAQABAoIBAQC121nNfnoeV/3j
    bEwika/3yYcDZCi+gQW48ETqb7pstxf4AkcUPfmwrLA8y1HHKbqgWCsEkB+r6bj7
    S2i7zR3ogVodC8VqWUCji8fNb8yWNc6c85ERWxvwDepPkZgRrbyUh87ztF3Oj9FN
    RE5yTowVlHo6scFlm7lqZQgjz8g3bDV+V9AAVP9G41rSZUv/L1Enmlg0rgSiM869
    SBZbyyj7mNJ6fpAS7YCZYMIeqTAaeCYDTWbIzW00nRfUMJ3U+HjBFUPPbfRwrPgR
    4zondisMfTWz+TnbMouQQdeS3EswqkZvf3wp/DodoKvGm/RgOIr+MkTlyhHQK9bj
    0Etnro/BAoGBAON7B8mbKJkqBXWjpv55xefEflZ9ZYtYG81kj2R2BLLcL0rc0iSS
    9V9o+/6UH0uBg3TWTySpMNy82R9CMd27m90W9sMeE7XsbblvX+yYugK8sYNP438O
    HQaywNFNJTJeGC+qLHaFmqd8+eXZ9cSKb7tOjQ/vAKa2ahXj9qGPf6BTAoGBAM47
    oNYCMRt/+IpwPLgwhbR+l3a7jBFHgXq5Mctfx35xiEGjobt6MBsKIBSMHEfqRj90
    CdfcvACp8MEygkyG/cmlE5kUD67Tg4dZwq77Vx4cj8+4AetrWpv//yTS+ktKdbtt
    w6g0C9m2Gbj1WPD8JlvL7f+/Vpqas67bwjM423xpAoGASl+oLScYf/M4M70c1SiV
    JvCcacS31XYqKN4O78aSRLQulihaYHDX3qjhctuU28ftZd7Ho3HZsuHfjxPCX/99
    tyxR43tK8HjrauxaDW3lqw1scEVHWPwRS2ZYGlZBqhUPjU3zGZEW/lmjDp5Tdz3X
    yAKnpiT7LoaHar7MnQfgr1cCgYEAlZSuLUrdr2J8NHz/rWCUObvvw9B34TiJ8ydL
    tIS9vzo9Z851SfNv3MzVQ9Hz2T1UwkU5tnWFbr3Tv20REMyAWrb+pfLlBRqotY0n
    JZ9rKo3wyOpfig8NY0SkHGNh4yYYil8soF1PkxL/SSW64t8gO0iIUQzIlc5LMTJ3
    gotktrECgYBarJctcJDcp7sTU0gSnKFaoYkMaMX8A+X/lmaep0ZwEowsl+D0AcD7
    xkFoJOfnfubi4GkGWP/AMWuU/s75kTXbImiyNgcn/S9J66ffLp96GZxmmBh21QP1
    +LdAlcHpBG7F7ZS0YuUqMZJd9EyfRQ0fxZg2QpQPrg9kw7fBqZPVkw==
    -----END RSA PRIVATE KEY-----
    """,
    home_org: "erlef-cna"
  ],
  hex_api: [plug: {Req.Test, Varsel.HexPm}],
  # hexpm's dev fixture key, which its test config pins under this kid.
  hex_signing_key:
    ~s({"crv":"P-256","d":"2jjObl1K0ZWiDxXdm5TXO2jDrnbNNuCeguEfO3SePkk","kid":"varsel-test","kty":"EC","x":"E34oPnnGyf9799k058t0zBpEo6cMDYDaFmmEEt2ePLw","y":"ajZ6c2ekFLfW1H-YBYlJKcKXpnfyu88FF2_PoewQCCU"}),
  cwe_catalog: [plug: {Req.Test, Varsel.CWE.Weakness}],
  capec_catalog: [plug: {Req.Test, Varsel.CAPEC.AttackPattern}],
  otp_versions_table: [plug: {Req.Test, Varsel.Cases.Derivation.OtpVersionsTable}],
  git_backend: Varsel.Test.StubGitBackend,
  mitre_cve_api: [
    base_url: "https://cveawg-test.mitre.org/api",
    org: "test-org",
    user: "test-user@example.com",
    api_key: "test-api-key",
    plug: {Req.Test, Varsel.CVE.MitreCveApi}
  ],
  hex_intake: [
    # Public half of a throwaway keypair; the private half lives in
    # VarselWeb.HexServiceTokenFixture.
    jwks:
      ~s({"keys":[{"crv":"P-256","kid":"hexpm-test","kty":"EC","x":"4pRM_ZlHTfTHVvAIxDEBraNmq06ojzDzL2MIHUzkqLk","y":"5HMC6Ycg9OjJGFbFs46n8rCTxB6VyGWcsLR3bnNWEtU"}]})
  ],
  oauth2_issuer_url: "http://localhost:4002",
  oauth2_resource_url: "http://localhost:4002",
  oauth2_signing_secret: "test-oauth2-signing-secret"
