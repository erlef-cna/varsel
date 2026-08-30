# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.MixProject do
  use Mix.Project

  def project do
    [
      app: :varsel,
      version: "0.3.5",
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
      ],
      usage_rules: usage_rules()
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
  #
  # `dev/` holds the developer tooling (storybook, Oban Web, LiveDashboard,
  # AshAdmin and the mailbox/error-page previews) and its router. Several of
  # those dependencies are `only: [:dev, :test]`, and Elixir resolves an
  # `import` even inside a branch it discards, so the calls cannot sit in the
  # main router behind a compile-time flag — they need a directory that is not
  # compiled at all in production.
  defp elixirc_paths(:dev), do: ["lib", "dev"]
  defp elixirc_paths(:test), do: ["lib", "dev", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    # styler:sort
    [
      {:absinthe_phoenix, "~> 2.0"},
      {:ash, "~> 3.0"},
      {:ash_admin, "~> 1.0", runtime: Mix.env() in [:dev, :test]},
      {:ash_ai, github: "ash-project/ash_ai", ref: "043461cc2e56dec2ba1dcd9d6b9d17e02e8e3d05"},
      # override: ash_ai pins ash_authentication ~> 4.8 but only touches it in
      # dev-time generators; the OAuth2 server package needs 5.0.
      {:ash_authentication, "~> 5.0-rc", override: true},
      {:ash_authentication_oauth2_server, "~> 0.2"},
      {:ash_authentication_phoenix, "~> 3.0-rc"},
      {:ash_cloak, "~> 0.2"},
      {:ash_credo, "~> 0.17", only: [:dev, :test], runtime: false},
      {:ash_graphql, "~> 1.10"},
      {:ash_oban, "~> 0.8"},
      {:ash_paper_trail, "~> 0.6"},
      {:ash_phoenix, "~> 2.0"},
      {:ash_postgres, "~> 2.0"},
      {:ash_rate_limiter, "~> 2.0"},
      {:ash_state_machine, "~> 0.2"},
      {:bandit, "~> 1.5"},
      {:cidr, "~> 1.2"},
      {:cloak, "~> 1.1"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:cvss, "~> 0.1"},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:dns_cluster, "~> 0.3.0"},
      {:ecto_psql_extras, "~> 0.6", only: [:dev, :test]},
      {:ecto_sql, "~> 3.13"},
      {:esbuild, "~> 0.10", runtime: Mix.env() == :dev},
      {:ex_json_schema, "~> 0.10"},
      {:exgit, "~> 0.1.0"},
      {:exile, "~> 0.14"},
      {:gen_smtp, "~> 1.2"},
      {:gettext, "~> 1.0"},
      {:hammer, "~> 7.0"},
      {:heroicons,
       github: "tailwindlabs/heroicons", tag: "v2.2.0", sparse: "optimized", app: false, compile: false, depth: 1},
      {:hex_core, "~> 0.11"},
      {:igniter, "~> 0.6", only: [:dev, :test]},
      {:jason, "~> 1.2"},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:lumis, "~> 0.7.0"},
      {:mdex, "~> 0.13"},
      {:nimble_publisher, "~> 2.0"},
      {:oban, "~> 2.0"},
      {:oban_web, "~> 2.0", only: [:dev, :test]},
      {:phoenix, "~> 1.8.5"},
      {:phoenix_ecto, "~> 4.5"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_dashboard, "~> 0.9.0", only: [:dev, :test]},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 1.1"},
      {:phoenix_storybook, "~> 1.3", only: [:dev, :test]},
      {:picosat_elixir, "~> 0.2"},
      {:plug_content_security_policy, "~> 0.2"},
      {:postgrex, ">= 0.0.0"},
      {:purl, "~> 0.5.0"},
      {:remote_ip, "~> 1.2"},
      {:req, "~> 0.5"},
      {:saxy, "~> 1.6"},
      {:sobelow, "~> 0.14", only: [:dev, :test], runtime: false, warn_if_outdated: true},
      {:sourceror, "~> 1.8", only: [:dev, :test]},
      {:styler, "~> 1.0", only: [:dev, :test], runtime: false},
      {:swoosh, "~> 1.16"},
      {:tailwind, "~> 0.3", runtime: Mix.env() == :dev},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:tidewave, "~> 0.6", only: :dev},
      {:usage_rules, "~> 1.0", only: [:dev]}
    ]
  end

  # Release configuration for `mix release`, used to build the production
  # container. Assets are compiled ahead of the release via `assets.deploy`.
  defp releases do
    [
      varsel: [
        include_executables_for: [:unix],
        applications: [runtime_tools: :permanent],
        steps: [:assemble, &cache_lumis_languages/1, &drop_lumis_theme_css/1]
      ]
    ]
  end

  # Lumis fetches a language's parser (WASM from its CDN) the first time it is
  # used and keeps it under the lumis application's priv directory by default.
  # Fetching the configured languages into that directory of the assembled
  # release means the release boots with them. Every language is then loaded
  # and used from there, so a missing or broken parser fails the release.
  defp cache_lumis_languages(%Mix.Release{} = release) do
    languages = Application.fetch_env!(:varsel, :lumis_languages)
    lumis = release.applications[:lumis]
    data_dir = Path.join([release.path, "lib", "lumis-#{lumis[:vsn]}", "priv", "lumis"])

    File.mkdir_p!(data_dir)
    Application.put_env(:lumis, :data_dir, data_dir)
    {:ok, _apps} = Application.ensure_all_started(:lumis)
    {:ok, _paths} = Lumis.Languages.cache(languages)

    :ok = Lumis.Languages.load(languages)

    for language <- languages do
      {:ok, _html} = Lumis.highlight("x", formatter: {:html_linked, language: language})
    end

    release
  end

  # Lumis ships a stylesheet per theme for applications to copy; this one
  # generates its own (`mix generate_lumis_css`) and renders with `:html_linked`
  # classes, so nothing reads them at runtime.
  defp drop_lumis_theme_css(%Mix.Release{} = release) do
    lumis = release.applications[:lumis]
    File.rm_rf!(Path.join([release.path, "lib", "lumis-#{lumis[:vsn]}", "priv", "static"]))
    release
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
      # `tailwind storybook` is dev-only (see VarselWeb.Storybook) and so is
      # deliberately absent from assets.deploy.
      "assets.build": ["compile", "tailwind varsel", "tailwind storybook", "esbuild varsel"],
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

  defp usage_rules do
    [
      file: "AGENTS.md",
      usage_rules: ["usage_rules:all", :ash, :phoenix]
    ]
  end
end
