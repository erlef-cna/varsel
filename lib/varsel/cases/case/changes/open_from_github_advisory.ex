# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.OpenFromGitHubAdvisory do
  @moduledoc """
  Fills a new case from a GitHub security advisory and creates the child rows
  read out of it. See `Varsel.Cases.GitHubAdvisory.Import` for what an
  advisory can and cannot be read into.

  The advisory is read before the transaction, as the caller, so a draft is
  theirs to see or not as GitHub decides. Attributes are force-set: the case
  claims what the advisory states, and nothing a caller passed alongside.
  The advisory is recorded as the case's `Varsel.Cases.GitHubAdvisoryLink`.

  Each child goes in through its own `:add` action as the caller once the
  case exists (`Varsel.Cases.GitHubAdvisory.Apply`), so the validations and
  policies that apply to adding the row by hand apply here too. The first
  child refused takes the whole create down with it.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases.GitHubAdvisory.Apply
  alias Varsel.Cases.GitHubAdvisory.Fetch
  alias Varsel.Cases.GitHubAdvisory.Import

  @advisory_key :github_advisory

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    changeset
    |> Changeset.before_transaction(&fetch(&1, context.actor))
    |> Changeset.before_action(&fill/1)
    |> Changeset.after_action(&add_children(&1, &2, context))
  end

  defp fetch(changeset, actor) do
    case changeset |> Changeset.get_argument(:advisory_url) |> Fetch.fetch(actor) do
      {:ok, advisory} -> Changeset.put_context(changeset, @advisory_key, advisory)
      {:error, message} -> Changeset.add_error(changeset, field: :advisory_url, message: message)
    end
  end

  defp fill(%{valid?: false} = changeset), do: changeset

  defp fill(changeset) do
    advisory = changeset.context[@advisory_key]

    changeset
    |> Changeset.force_change_attributes(Import.case_params(advisory))
    |> Changeset.manage_relationship(:github_advisory_link, %{advisory: advisory},
      type: :create,
      on_no_match: {:create, :record}
    )
  end

  defp add_children(changeset, case_record, context) do
    opts = Ash.Context.to_opts(context)
    children = Import.child_params(changeset.context[@advisory_key])
    case_id = case_record.id

    with :ok <-
           children.weaknesses
           |> Apply.known_weaknesses()
           |> Apply.each(&Apply.add_weakness(&1, case_id, opts)),
         :ok <-
           children.credits
           |> Apply.credit_rows()
           |> Apply.each(&Apply.add_credit(&1, case_id, opts)),
         :ok <-
           children.affected
           |> Enum.with_index()
           |> Apply.each(fn {package, position} ->
             Apply.add_package(package, case_id, position, opts)
           end) do
      {:ok, case_record}
    end
  end
end
