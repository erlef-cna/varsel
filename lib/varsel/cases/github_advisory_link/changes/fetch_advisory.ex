# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Changes.FetchAdvisory do
  @moduledoc """
  Reads the advisory a link names before the transaction, as the actor, and
  leaves it in the changeset context for `StoreAdvisory`.

  A link being created names it by the `advisory_url` argument. An existing
  link names it by the repository and GHSA id it stored.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases.GitHubAdvisory.Fetch

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_transaction(changeset, &fetch(&1, context.actor))
  end

  defp fetch(%{action_type: :create} = changeset, actor) do
    changeset |> Changeset.get_argument(:advisory_url) |> Fetch.fetch(actor) |> store(changeset)
  end

  defp fetch(%{data: link} = changeset, actor) do
    link |> reference() |> Fetch.fetch_ref(actor) |> store(changeset)
  end

  defp reference(%{owner: owner, repo: repo, ghsa_id: ghsa_id}) when is_binary(owner) and is_binary(repo),
    do: %{owner: owner, repo: repo, ghsa_id: ghsa_id}

  defp reference(%{ghsa_id: ghsa_id}), do: %{ghsa_id: ghsa_id}

  defp store({:ok, advisory}, changeset), do: Changeset.put_context(changeset, :github_advisory, advisory)

  defp store({:error, message}, changeset) do
    Changeset.add_error(changeset, field: :advisory_url, message: message)
  end
end
