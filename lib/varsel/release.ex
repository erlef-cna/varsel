# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Release tasks run outside the usual authorization context: there is no actor,
# and no request that could carry one. What authorizes them is shell access to a
# fully configured server — someone who has that can already reach the database
# directly — so the Ash calls here pass `authorize?: false` by design.
# credo:disable-for-this-file AshCredo.Check.Warning.AuthorizeFalse

defmodule Varsel.Release do
  @moduledoc """
  Release tasks run inside the production release, e.g.

      bin/varsel eval "Varsel.Release.migrate"

  These start the minimal applications needed and never depend on Mix, which
  is not available in a release.
  """

  @app :varsel

  @doc "Run all pending migrations for every repo."
  def migrate do
    load_app()

    for repo <- repos() do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  @doc "Roll a repo back to the given migration version."
  def rollback(repo, version) do
    load_app()
    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end

  @doc """
  Grants the POC role to the user whose id is given on the command line:

      bin/promote-to-poc 0199…

  How a deployment gets its first POC: sign in once to create the account,
  then run this against that account's id. Setting a role otherwise requires
  an actor who is already a POC, which the first one has nobody to be.

  The id is read from `System.argv/0` rather than taken as an argument so the
  wrapper can pass it to `eval` as an argument instead of interpolating it
  into the evaluated expression.
  """
  def promote_to_poc do
    case System.argv() do
      [id] -> promote_to_poc(id)
      _otherwise -> raise ArgumentError, "expected exactly one argument, a user id"
    end
  end

  @doc "Grants the POC role to the user with `id`. See `promote_to_poc/0`."
  def promote_to_poc(id) when is_binary(id) do
    load_app()
    {:ok, _} = Application.ensure_all_started(@app)

    id
    |> Varsel.Accounts.get_user_by_id!(authorize?: false)
    |> Varsel.Accounts.set_user_role!(:poc, authorize?: false)
  end

  defp repos do
    Application.fetch_env!(@app, :ecto_repos)
  end

  defp load_app do
    Application.load(@app)
  end
end
