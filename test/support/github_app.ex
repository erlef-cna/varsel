# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.GitHubApp do
  @moduledoc """
  Seeds the GitHub App's credential cache for a test, so that the code
  under test finds installations and tokens without a request to GitHub.

  In the test environment, `Varsel.GitHub.Installation`,
  `Varsel.GitHub.InstallationLookup` and `Varsel.GitHub.UserInstallation`
  keep their rows in ETS tables that are private to the process that
  writes them. Each test starts with empty tables, and only the test
  process sees what it seeds. Another process, such as a task or a
  LiveView, has its own empty tables.

  The seeds go through the resources' own create and update actions with
  the context stamp their write policies require, so they run as a real
  actor:

      setup do
        poc = register_user("poc", :poc)
        supporter = register_user("supporter", :supporter)

        GitHubApp.seed_installation(poc, %{id: 7, account: "acme"},
          repositories: ["acme/lib"],
          token: "ghs_seeded"
        )

        GitHubApp.seed_user_installations(supporter, [7])
        %{poc: poc, supporter: supporter}
      end

  With these seeds, `Varsel.GitHub.installation_for_repository("acme",
  "lib", actor: poc)` answers installation 7,
  `Varsel.GitHub.installation_token(7, actor: poc)` answers `"ghs_seeded"`,
  and `Varsel.GitHub.user_installations(actor: supporter)` answers
  installation 7 for the supporter. A seeded answer stays fresh for the
  cache lifetime, ten minutes.
  """

  alias Varsel.Accounts.User
  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.InstallationLookup
  alias Varsel.GitHub.UserInstallation

  @stamp %{private: %{installation_sync: true}}

  @doc """
  Stores an installation as if a lookup had found it, written as `actor`.

  `attrs` needs `:id` and `:account`. `:kind` defaults to `:organization`
  and `:repository_selection` to `:all`. An organization's installation
  also answers the lookup of its account.

  Options:

  - `repositories`: the `owner/repo` names whose lookup answers this
    installation.
  - `token`: an installation token to store on the row. A `:token` call by
    a POC returns it without minting.
  - `token_expires_at`: when that token expires. Defaults to one hour from
    now.
  - `fetched_at`: when GitHub answered. Defaults to now. An earlier time
    makes the lookups stale.
  """
  @spec seed_installation(User.t(), map(), keyword()) :: Installation.t()
  def seed_installation(actor, attrs, opts \\ []) do
    fetched_at = Keyword.get(opts, :fetched_at, DateTime.utc_now())

    installation =
      Ash.create!(
        Installation,
        Map.merge(
          %{kind: :organization, repository_selection: :all, fetched_at: fetched_at},
          attrs
        ),
        action: :store,
        actor: actor,
        context: @stamp
      )

    subjects =
      if installation.kind == :organization,
        do: [to_string(installation.account) | Keyword.get(opts, :repositories, [])],
        else: Keyword.get(opts, :repositories, [])

    Enum.each(subjects, &store_lookup(actor, &1, installation.id, fetched_at))

    case Keyword.fetch(opts, :token) do
      {:ok, token} ->
        expires_at =
          Keyword.get(opts, :token_expires_at, DateTime.shift(DateTime.utc_now(), hour: 1))

        Ash.update!(installation, %{token: token, token_expires_at: expires_at},
          action: :store_token,
          actor: actor,
          context: @stamp
        )

      :error ->
        installation
    end
  end

  @doc """
  Stores GitHub's answer that the App is not installed on `subject`, an
  `owner/repo` name or an account, written as `actor`.
  """
  @spec seed_not_installed(User.t(), String.t()) :: :ok
  def seed_not_installed(actor, subject) do
    store_lookup(actor, subject, nil, DateTime.utc_now())
  end

  @doc """
  Stores the installations that the GitHub token of `user` reaches, written
  as `user`. The store action takes the user from the actor, so each
  person's rows are seeded as that person.
  """
  @spec seed_user_installations(User.t(), [pos_integer()], keyword()) :: [
          UserInstallation.t()
        ]
  def seed_user_installations(user, installation_ids, opts \\ []) do
    fetched_at = Keyword.get(opts, :fetched_at, DateTime.utc_now())

    Enum.map(installation_ids, fn id ->
      Ash.create!(UserInstallation, %{installation_id: id, fetched_at: fetched_at},
        action: :store,
        actor: user,
        context: @stamp
      )
    end)
  end

  defp store_lookup(actor, subject, installation_id, fetched_at) do
    Ash.create!(
      InstallationLookup,
      %{
        subject: String.downcase(subject),
        installation_id: installation_id,
        fetched_at: fetched_at
      },
      action: :store,
      actor: actor,
      context: @stamp
    )

    :ok
  end
end
