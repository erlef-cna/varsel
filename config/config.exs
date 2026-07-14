# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :ash,
  allow_forbidden_field_for_relationships_by_default?: true,
  include_embedded_source_by_default?: false,
  show_keysets_for_all_actions?: false,
  default_page_type: :keyset,
  policies: [no_filter_static_forbidden_reads?: false],
  keep_read_action_loads_when_loading?: false,
  default_actions_require_atomic?: true,
  read_action_after_action_hooks_in_order?: true,
  bulk_actions_default_to_errors?: true,
  transaction_rollback_on_error?: true,
  redact_sensitive_values_in_errors?: true,
  known_types: [AshPostgres.Timestamptz, AshPostgres.TimestamptzUsec, Varsel.Types.CVSS]

config :ash_graphql, authorize_update_destroy_with_error?: true, json_type: :json

config :ash_oban, pro?: false

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  varsel: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Resolve `file:` references in the vendored CVE record schema (priv/cve_schema)
config :ex_json_schema, :remote_schema_resolver, {Varsel.CVE.CveSchema, :resolve_ref}

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

config :spark,
  formatter: [
    remove_parens?: true,
    "Ash.Resource": [
      section_order: [
        :admin,
        :graphql,
        :authentication,
        :token,
        :user_identity,
        :postgres,
        :resource,
        :code_interface,
        :actions,
        :policies,
        :pub_sub,
        :preparations,
        :changes,
        :validations,
        :multitenancy,
        :attributes,
        :relationships,
        :calculations,
        :aggregates,
        :identities
      ]
    ],
    "Ash.Domain": [
      section_order: [
        :admin,
        :graphql,
        :resources,
        :policies,
        :authorization,
        :domain,
        :execution
      ]
    ]
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.1.12",
  varsel: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),

    # Import environment specific config. This must remain at the bottom
    # of this file so it overrides the configuration defined above.
    cd: Path.expand("..", __DIR__)
  ]

config :varsel, Oban,
  engine: Oban.Engines.Basic,
  notifier: Oban.Notifiers.Postgres,
  queues: [
    default: 10,
    cve_publishing: 1,
    cve_pool: 1,
    cwe_sync: 1,
    capec_sync: 1,
    osv_sync: 1
  ],
  repo: Varsel.Repo,
  plugins: [{Oban.Plugins.Cron, []}]

# Configure the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :varsel, Varsel.Mailer, adapter: Swoosh.Adapters.Local

# Configure the endpoint
config :varsel, VarselWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: VarselWeb.ErrorHTML, json: VarselWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Varsel.PubSub,
  live_view: [signing_salt: "zOuaRJlV"]

# The "from" address used for CNA notification emails (e.g. new vulnerability
# report submissions sent to POCs).
config :varsel, :cna_email_from, "cna@erlef.org"

config :varsel,
  cve_pool_min_size: 5,
  ecto_repos: [Varsel.Repo],
  generators: [timestamp_type: :utc_datetime],
  ash_domains: [
    Varsel.CAPEC,
    Varsel.CWE,
    Varsel.CVE,
    Varsel.Accounts
  ]

import_config "#{config_env()}.exs"
