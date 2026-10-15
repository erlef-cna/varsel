# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.SyncGitHubInstallations do
  @moduledoc """
  Makes the person's `Varsel.GitHub.UserInstallation` rows match the
  installations of the GitHub App that their own GitHub token reaches.

  Before the transaction, GitHub lists the installations and, for each
  selective one, the repositories the person can access. Inside the
  transaction each installation is stored as a `Varsel.GitHub.Installation`,
  the listed repositories are added, the person's links are replaced, and
  `github_installations_synced_at` is set. The person's token lists only the
  repositories the person can access, so this change adds repository rows
  and never removes them. `:sync_all` sees every repository and removes
  the ones GitHub no longer lists.

  A person without a GitHub identity, or whose token GitHub refuses,
  reaches nothing, so the change removes their links.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.GitHub
  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.RequestFailed
  alias Varsel.GitHub.Sync
  alias Varsel.GitHub.UserToken

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    changeset
    |> Changeset.before_transaction(&list/1)
    |> Changeset.before_action(&store(&1, %{context | source_context: &1.context}))
  end

  defp list(%{data: user} = changeset) do
    case reached(user) do
      {:ok, listed} -> Changeset.put_context(changeset, :github_installations, listed)
      {:error, reason} -> Changeset.add_error(changeset, RequestFailed.exception(reason: reason))
    end
  end

  defp reached(user) do
    with {:ok, token} <- UserToken.fetch(user),
         {:ok, installations} <- App.user_installations(token) do
      with_repositories(installations, token)
    else
      {:error, reason} when reason in [:no_github_identity, :unauthorized] -> {:ok, []}
      {:error, reason} -> {:error, reason}
    end
  end

  defp with_repositories(installations, token) do
    Enum.reduce_while(installations, {:ok, []}, fn installation, {:ok, listed} ->
      case repositories(installation, token) do
        {:ok, repositories} -> {:cont, {:ok, [{installation, repositories} | listed]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp repositories(%{repository_selection: :selected, suspended_at: nil, id: id}, token),
    do: App.user_installation_repositories(token, id)

  defp repositories(_installation, _token), do: {:ok, []}

  defp store(%{data: user} = changeset, context) do
    opts = Sync.opts(context)
    listed = changeset.context.github_installations

    Enum.each(listed, fn {installation, repositories} ->
      GitHub.sync_installation!(installation, opts)

      Enum.each(repositories, fn %{owner: owner, repo: repo} ->
        GitHub.sync_installation_repository!(
          %{installation_id: installation.id, owner: owner, repo: repo},
          opts
        )
      end)
    end)

    link(user, Enum.map(listed, fn {installation, _repositories} -> installation.id end), opts)

    Changeset.force_change_attribute(
      changeset,
      :github_installations_synced_at,
      DateTime.utc_now()
    )
  end

  defp link(user, ids, opts) do
    [query: [filter: [user_id: user.id]]]
    |> Keyword.merge(opts)
    |> GitHub.list_user_installations!()
    |> Enum.reject(&(&1.installation_id in ids))
    |> Enum.each(&GitHub.forget_user_installation!(&1, opts))

    Enum.each(
      ids,
      &GitHub.sync_user_installation!(%{user_id: user.id, installation_id: &1}, opts)
    )
  end
end
