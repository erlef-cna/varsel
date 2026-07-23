# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.MixProject do
  use Mix.Project

  def project do
    [
      app: :varsel,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_options: [warnings_as_errors: true],
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      releases: releases(),
      compilers: [:phoenix_live_view] ++ Mix.compilers(),
      listeners: [Phoenix.CodeReloader],
      consolidate_protocols: Mix.env() != :dev,
      dialyzer: [
        ignore_warnings: ".dialyzer_ignore.exs",
        # Fail if an ignore entry no longer matches any warning, so stale
        # skips (e.g. once the upstream fix lands) get cleaned up.
        list_unused_filters: true,
        # precommit runs in MIX_ENV=test, so the test-support helpers are
        # analysed too; add ExUnit to the PLT so its callbacks resolve, and
        # Mix for the tasks under lib/mix/tasks.
        plt_add_apps: [:ex_unit, :mix]
      ]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Varsel.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    # styler:sort
    [
      {:absinthe_phoenix, "~> 2.0"},
      {:ash, "~> 3.0"},
      {:ash_admin, "~> 1.0"},
      {:ash_ai, "~> 0.6"},
      # override: ash_ai pins ash_authentication ~> 4.8 but only touches it in
      # dev-time generators; the OAuth2 server package needs 5.0.
      {:ash_authentication, "~> 5.0-rc", override: true},
      {:ash_authentication_oauth2_server, "~> 0.2"},
      {:ash_authentication_phoenix, "~> 3.0-rc"},
      {:ash_cloak, "~> 0.2"},
      {:ash_graphql, "~> 1.0"},
      {:ash_oban, "~> 0.8"},
      {:ash_paper_trail, "~> 0.6"},
      {:ash_phoenix, "~> 2.0"},
      {:ash_postgres, "~> 2.0"},
      {:ash_state_machine, "~> 0.2"},
      {:bandit, "~> 1.5"},
      {:cloak, "~> 1.1"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:cvss, "~> 0.1"},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:dns_cluster, "~> 0.2.0"},
      {:ecto_sql, "~> 3.13"},
      {:esbuild, "~> 0.10", runtime: Mix.env() == :dev},
      {:ex_json_schema, "~> 0.10"},
      {:exgit, "~> 0.1.0"},
      {:gen_smtp, "~> 1.2"},
      {:gettext, "~> 1.0"},
      {:heroicons,
       github: "tailwindlabs/heroicons", tag: "v2.2.0", sparse: "optimized", app: false, compile: false, depth: 1},
      {:hex_core, "~> 0.11"},
      {:igniter, "~> 0.6", only: [:dev, :test]},
      {:jason, "~> 1.2"},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:lumis, "~> 0.6"},
      {:mdex, "~> 0.13"},
      {:nimble_publisher, "~> 2.0"},
      {:oban, "~> 2.0"},
      {:oban_web, "~> 2.0"},
      {:phoenix, "~> 1.8.5"},
      {:phoenix_ecto, "~> 4.5"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_dashboard, "~> 0.8.3"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 1.1"},
      {:picosat_elixir, "~> 0.2"},
      {:plug_content_security_policy, "~> 0.2"},
      {:postgrex, ">= 0.0.0"},
      {:purl, "~> 0.4.0"},
      {:req, "~> 0.5"},
      {:saxy, "~> 1.6"},
      {:sobelow, "~> 0.14", only: [:dev, :test], runtime: false, warn_if_outdated: true},
      {:sourceror, "~> 1.8", only: [:dev, :test]},
      {:styler, "~> 1.0"},
      {:swoosh, "~> 1.16"},
      {:tailwind, "~> 0.3", runtime: Mix.env() == :dev},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:tidewave, "~> 0.6", only: :dev}
    ]
  end

  # Release configuration for `mix release`, used to build the production
  # container. Assets are compiled ahead of the release via `assets.deploy`.
  defp releases do
    [
      varsel: [
        include_executables_for: [:unix],
        applications: [runtime_tools: :permanent]
      ]
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get", "ash.setup", "assets.setup", "assets.build", "run priv/repo/seeds.exs"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ash.setup --quiet", "test"],
      "assets.setup": [
        "tailwind.install --if-missing",
        "esbuild.install --if-missing",
        "cmd --cd assets npm install"
      ],
      "assets.build": ["compile", "tailwind varsel", "esbuild varsel"],
      "assets.deploy": [
        "tailwind varsel --minify",
        "esbuild varsel --minify",
        "phx.digest"
      ],
      precommit: [
        "compile",
        "deps.unlock --unused",
        "format",
        "credo --strict",
        "sobelow",
        "dialyzer",
        "test"
      ]
    ]
  end
end
