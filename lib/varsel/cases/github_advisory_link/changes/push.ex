# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Changes.Push do
  @moduledoc """
  Writes the chosen fields of the case onto the advisory at GitHub, as the
  actor, before the link's `:push` update, and leaves what GitHub answered in
  the changeset context for `StoreAdvisory`.

  The write carries the actor's own GitHub token. GitHub attributes the
  change to them and decides whether they may make it. A person credited on
  the case without a linked GitHub account cannot be stated on the advisory
  and comes back on the link's `skipped_credits` metadata.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.GitHubAdvisory.Refusal
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.UserToken

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    changeset
    |> Changeset.before_transaction(&push(&1, context))
    |> Changeset.after_action(fn changeset, link ->
      {:ok,
       Ash.Resource.put_metadata(
         link,
         :skipped_credits,
         changeset.context[:skipped_credits] || []
       )}
    end)
  end

  defp push(%{data: link} = changeset, context) do
    fields = Changeset.get_argument(changeset, :fields)
    opts = Ash.Context.to_opts(context)

    with {:ok, {owner, repo}} <- repository(link),
         {:ok, token} <- token(context.actor),
         {:ok, case_record} <-
           Cases.get_case(link.case_id, Keyword.put(opts, :load, Export.load())),
         %{body: body, skipped_credits: skipped} = Export.body(case_record, fields, link.advisory),
         {:ok, advisory} <- update(owner, repo, link.ghsa_id, body, token) do
      changeset
      |> Changeset.put_context(:github_advisory, advisory)
      |> Changeset.put_context(:skipped_credits, skipped)
    else
      {:error, message} when is_binary(message) ->
        Changeset.add_error(changeset, field: :fields, message: message)

      {:error, error} ->
        Changeset.add_error(changeset, error)
    end
  end

  defp repository(%{owner: owner, repo: repo}) when is_binary(owner) and is_binary(repo), do: {:ok, {owner, repo}}

  defp repository(_global_entry), do: {:error, "cannot be pushed: the advisory is a global database entry"}

  defp token(actor) do
    case UserToken.fetch(actor) do
      {:ok, token} -> {:ok, token}
      {:error, reason} -> {:error, UserToken.message(reason)}
    end
  end

  defp update(owner, repo, ghsa_id, body, token) do
    case Advisories.update(owner, repo, ghsa_id, body, token: token) do
      {:ok, advisory} ->
        {:ok, advisory}

      answer ->
        {:error, Refusal.message(answer, "was refused: GitHub shows you no such advisory")}
    end
  end
end
