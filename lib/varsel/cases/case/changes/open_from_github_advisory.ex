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

  With `content?: false` the case takes only the advisory's title and the
  link, and no child rows.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Resource.Change
  alias Varsel.Cases.GitHubAdvisory.Apply
  alias Varsel.Cases.GitHubAdvisory.Fetch
  alias Varsel.Cases.GitHubAdvisory.Import

  @advisory_key :github_advisory

  @impl Change
  def init(opts) do
    if is_boolean(Keyword.get(opts, :content?, true)) do
      {:ok, opts}
    else
      {:error, "`content?` must be a boolean"}
    end
  end

  @impl Change
  def change(changeset, opts, context) do
    content? = Keyword.get(opts, :content?, true)

    changeset
    |> attest_or_fetch(context.actor)
    |> Changeset.before_action(&fill(&1, content?))
    |> children(content?, context)
  end

  defp children(changeset, true, context), do: Changeset.after_action(changeset, &add_children(&1, &2, context))

  defp children(changeset, false, _context), do: changeset

  # An attested open carries the advisory the POC read with `gh`. Nothing
  # reads it again from GitHub, as `RecordAnswer` states for every answer.
  defp attest_or_fetch(%{action: %{name: :open_from_github_advisory_attested}} = changeset, _actor) do
    Changeset.put_context(
      changeset,
      @advisory_key,
      Changeset.get_argument(changeset, :advisory)
    )
  end

  defp attest_or_fetch(changeset, actor) do
    Changeset.before_transaction(changeset, &fetch(&1, actor))
  end

  defp fetch(changeset, actor) do
    case changeset |> Changeset.get_argument(:advisory_url) |> Fetch.fetch(actor) do
      {:ok, advisory} -> Changeset.put_context(changeset, @advisory_key, advisory)
      {:error, message} -> Changeset.add_error(changeset, field: :advisory_url, message: message)
    end
  end

  defp fill(%{valid?: false} = changeset, _content?), do: changeset

  defp fill(changeset, content?) do
    advisory = changeset.context[@advisory_key]
    params = Import.case_params(advisory)

    changeset
    |> Changeset.force_change_attributes(if(content?, do: params, else: Map.take(params, [:title])))
    |> Changeset.manage_relationship(:github_advisory_link, %{advisory: advisory},
      type: :create,
      on_no_match: {:create, :record},
      # The link's identities report against :advisory_url, this action's own
      # argument. A path would make AshPhoenix look for a nested form of that
      # name, so the error has to carry none to reach the field.
      error_path: []
    )
  end

  defp add_children(changeset, case_record, context) do
    opts = Ash.Context.to_opts(context)
    children = Import.child_params(changeset.context[@advisory_key])
    case_id = case_record.id

    with :ok <- Apply.each(children.metrics, &Apply.add_metric(&1, case_id, opts)),
         :ok <-
           children.weaknesses
           |> Apply.known_weaknesses()
           |> Apply.each(&Apply.add_weakness(&1, case_id, opts)),
         :ok <-
           children.credits
           |> Apply.credit_rows()
           |> Apply.each(&Apply.add_credit(&1, case_id, opts)),
         :ok <- Apply.each(children.affected, &Apply.add_package(&1, case_id, opts)) do
      {:ok, case_record}
    end
  end
end
