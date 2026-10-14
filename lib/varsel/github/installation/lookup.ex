# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.Lookup do
  @moduledoc """
  Answers which installation of the GitHub App covers a repository or an
  organization.

  An answer in `Varsel.GitHub.InstallationLookup` that is less than ten
  minutes old answers from the cache. Otherwise `Varsel.GitHub.App` asks
  GitHub, and the answer is stored, positive or negative. An App that is
  not configured has no installations and stores nothing.
  """

  use Ash.Resource.ManualRead

  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.RequestFailed
  alias Varsel.GitHub.Installation
  alias Varsel.GitHub.InstallationLookup
  alias Varsel.GitHub.Sync

  @lifetime to_timeout(minute: 10)

  @impl Ash.Resource.ManualRead
  def read(query, _data_layer_query, opts, context) do
    if App.configured?() do
      query.arguments
      |> target(opts[:scope])
      |> lookup(Sync.opts(context))
    else
      {:ok, []}
    end
  end

  defp target(%{owner: owner, repo: repo}, :repository),
    do: {String.downcase("#{owner}/#{repo}"), fn -> App.repository_installation(owner, repo) end}

  defp target(%{account: account}, :org), do: {String.downcase(account), fn -> App.org_installation(account) end}

  defp lookup({subject, ask}, opts) do
    case cached(subject, opts) do
      {:ok, installations} -> {:ok, installations}
      :stale -> fetch(subject, ask.(), opts)
      {:error, error} -> {:error, error}
    end
  end

  defp cached(subject, opts) do
    case Ash.get(InstallationLookup, subject, [not_found_error?: false] ++ opts) do
      {:ok, %InstallationLookup{} = answer} ->
        if fresh?(answer), do: installation(answer, opts), else: :stale

      {:ok, nil} ->
        :stale

      {:error, error} ->
        {:error, error}
    end
  end

  defp fresh?(%InstallationLookup{fetched_at: fetched_at}),
    do: DateTime.diff(DateTime.utc_now(), fetched_at, :millisecond) < @lifetime

  defp installation(%InstallationLookup{installation_id: nil}, _opts), do: {:ok, []}

  defp installation(%InstallationLookup{installation_id: id}, opts) do
    case Ash.get(Installation, id, [not_found_error?: false] ++ opts) do
      {:ok, %Installation{} = installation} -> {:ok, [installation]}
      {:ok, nil} -> :stale
      {:error, error} -> {:error, error}
    end
  end

  defp fetch(subject, {:ok, described}, opts) do
    with {:ok, _stored} <- Ash.create(Installation, described, [action: :store] ++ opts),
         {:ok, _answer} <- store(subject, described.id, opts),
         {:ok, installation} <- Ash.get(Installation, described.id, opts) do
      {:ok, [installation]}
    end
  end

  defp fetch(subject, :not_installed, opts) do
    with {:ok, _answer} <- store(subject, nil, opts), do: {:ok, []}
  end

  defp fetch(_subject, {:error, reason}, _opts), do: {:error, RequestFailed.exception(reason: reason)}

  defp store(subject, installation_id, opts) do
    Ash.create(
      InstallationLookup,
      %{subject: subject, installation_id: installation_id},
      [action: :store] ++ opts
    )
  end
end
