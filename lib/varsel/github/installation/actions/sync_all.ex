# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.Actions.SyncAll do
  @moduledoc """
  Runs `Varsel.GitHub.Installation`'s `:sync_all` action.

  GitHub's list of the App's installations replaces the stored one. Each
  selective installation that is not suspended then lists its repositories
  with its own installation token, and that list replaces its stored
  repositories. An installation that covers all repositories keeps none.

  Failures are isolated per installation: the run collects every error and
  raises at the end, so one installation does not stop the others and Oban
  retries the whole sweep.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.GitHub
  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.RequestFailed
  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.Installation.Mint
  alias Varsel.GitHub.Sync

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    if App.configured?() do
      sync(Sync.opts(context))
    else
      {:ok, :ok}
    end
  end

  defp sync(opts) do
    case App.installations() do
      {:ok, described} ->
        Enum.each(described, &GitHub.sync_installation!(&1, opts))
        forget_gone(Enum.map(described, & &1.id), opts)

        case Enum.flat_map(described, &sync_repositories(&1, opts)) do
          [] -> {:ok, :ok}
          errors -> raise "Failed to sync GitHub App repositories: #{inspect(errors)}"
        end

      {:error, reason} ->
        {:error, RequestFailed.exception(reason: reason)}
    end
  end

  defp forget_gone(ids, opts) do
    gone = Ash.Query.filter(Installation, id not in ^ids)

    [query: gone]
    |> Keyword.merge(opts)
    |> GitHub.list_installations!()
    |> Enum.each(&GitHub.forget_installation!(&1, opts))
  end

  defp sync_repositories(%{suspended_at: %DateTime{}}, _opts), do: []

  defp sync_repositories(%{id: id, repository_selection: :all}, opts) do
    replace_repositories(id, [], opts)
    []
  end

  defp sync_repositories(%{id: id, repository_selection: :selected}, opts) do
    with {:ok, token} <- Mint.token(id, opts),
         {:ok, repositories} <- App.installation_repositories(token) do
      replace_repositories(id, repositories, opts)
      []
    else
      {:error, reason} -> [{id, reason}]
    end
  end

  defp replace_repositories(installation_id, repositories, opts) do
    listed = MapSet.new(repositories, &key/1)

    stored =
      GitHub.list_installation_repositories!([query: [filter: [installation_id: installation_id]]] ++ opts)

    stored
    |> Enum.reject(&MapSet.member?(listed, key(&1)))
    |> Enum.each(&GitHub.forget_installation_repository!(&1, opts))

    known = MapSet.new(stored, &key/1)

    repositories
    |> Enum.reject(&MapSet.member?(known, key(&1)))
    |> Enum.each(fn %{owner: owner, repo: repo} ->
      GitHub.sync_installation_repository!(
        %{installation_id: installation_id, owner: owner, repo: repo},
        opts
      )
    end)
  end

  defp key(%{owner: owner, repo: repo}), do: {String.downcase(to_string(owner)), String.downcase(to_string(repo))}
end
