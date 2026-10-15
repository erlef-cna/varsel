# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.GitHubApp do
  @moduledoc """
  Seeds the GitHub App's installations for a test, so that the code under
  test finds installations, repositories, tokens and who reaches what
  without a request to GitHub.

  The seeds are ordinary rows in the test's sandboxed database, so every
  process that the test owns or allows sees them, a LiveView too. They go
  through the same write actions that the syncs use, with the context the
  syncs run with: the AshOban flag and the `Varsel.GitHub.Sync` stamp.

      setup do
        supporter = register_user("supporter", :supporter)

        GitHubApp.seed_installation(%{id: 7, account: "acme", repository_selection: :selected},
          repositories: ["acme/lib"],
          token: "ghs_seeded"
        )

        GitHubApp.seed_user_installations(supporter, [7])
        %{supporter: supporter}
      end

  With these seeds, `Varsel.GitHub.installation_for_repository("acme",
  "lib", actor: supporter)` answers installation 7, and
  `Varsel.GitHub.installation_token(7, actor: poc)` answers `"ghs_seeded"`
  to a POC.
  """

  alias Varsel.Accounts.User
  alias Varsel.GitHub
  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.UserInstallation

  @sync %{private: %{ash_oban?: true, github_sync: true}}

  @doc """
  Stores an installation as if `sync_all` had listed it.

  `attrs` needs `:id` and `:account`. `:kind` defaults to `:organization`,
  `:repository_selection` to `:all`, and `:suspended_at` to nil.

  Options:

  - `repositories`: the `owner/repo` names that a selective installation
    covers.
  - `token`: an installation token to store on the row. A `:token` call by
    a POC returns it without minting.
  - `token_expires_at`: when that token expires. Defaults to one hour from
    now.
  """
  @spec seed_installation(map(), keyword()) :: Installation.t()
  def seed_installation(attrs, opts \\ []) do
    installation =
      %{kind: :organization, repository_selection: :all}
      |> Map.merge(attrs)
      |> GitHub.sync_installation!(context: @sync)

    opts
    |> Keyword.get(:repositories, [])
    |> Enum.each(fn name ->
      [owner, repo] = String.split(name, "/")

      GitHub.sync_installation_repository!(
        %{installation_id: installation.id, owner: owner, repo: repo},
        context: @sync
      )
    end)

    case Keyword.fetch(opts, :token) do
      {:ok, token} ->
        expires_at =
          Keyword.get(opts, :token_expires_at, DateTime.shift(DateTime.utc_now(), hour: 1))

        GitHub.store_installation_token!(
          installation,
          %{token: token, token_expires_at: expires_at},
          context: @sync
        )

      :error ->
        installation
    end
  end

  @doc """
  Stores that the GitHub token of `user` reaches the installations
  `installation_ids`, as if `:sync_github_installations` had listed them.
  Seed the installations first.
  """
  @spec seed_user_installations(User.t(), [pos_integer()]) :: [UserInstallation.t()]
  def seed_user_installations(user, installation_ids) do
    Enum.map(
      installation_ids,
      &GitHub.sync_user_installation!(%{user_id: user.id, installation_id: &1}, context: @sync)
    )
  end
end
