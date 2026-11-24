# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Changes.Pull do
  @moduledoc """
  Takes the chosen fields of the stored advisory over onto the case, through
  the case's own actions as the actor, inside the link's `:pull` update.

  A scalar (title, a description section, CVSS) replaces the case's value.
  A description section writes its case attribute
  (`Varsel.Cases.GitHubAdvisory.Sections`). The CVSS vector is the case's
  GENERAL score. A set (CWEs, credits,
  affected packages) gains what the advisory has and the case lacks, and
  loses nothing. Taking something away is a person's call on the workspace.
  An affected package is matched the way the diff matches it and arrives
  with its channels and no boundaries (`Varsel.Cases.GitHubAdvisory.Apply`).
  The first write refused takes the whole pull down with it.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Apply
  alias Varsel.Cases.GitHubAdvisory.Diff
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.GitHubAdvisory.Import
  alias Varsel.Cases.GitHubAdvisory.People
  alias Varsel.Cases.GitHubAdvisory.Sections

  @scalars [:title | Sections.pullable_fields()]

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_action(changeset, &pull(&1, Ash.Context.to_opts(context)))
  end

  defp pull(%{valid?: false} = changeset, _opts), do: changeset

  defp pull(%{data: link} = changeset, opts) do
    fields = Changeset.get_argument(changeset, :fields)

    with {:ok, case_record} <-
           Cases.get_case(link.case_id, Keyword.put(opts, :load, Export.load())),
         {:ok, case_record} <- pull_scalars(fields, case_record, link.advisory, opts),
         :ok <- pull_sets(fields, case_record, link.advisory, opts) do
      changeset
    else
      {:error, error} -> Changeset.add_error(changeset, error)
    end
  end

  defp pull_scalars(fields, case_record, advisory, opts) do
    attributes = for field <- fields, field in @scalars, do: attribute(field)
    params = advisory |> Import.case_params() |> Map.take(attributes)

    if map_size(params) == 0,
      do: {:ok, case_record},
      else: Cases.edit_case(case_record, params, opts)
  end

  defp attribute(:title), do: :title
  defp attribute(field), do: Sections.attribute(field)

  defp pull_sets(fields, case_record, advisory, opts) do
    children = Import.child_params(advisory)

    Apply.each(fields -- @scalars, fn field ->
      with :ok <- pull_set(field, children, case_record, opts), do: {:ok, field}
    end)
  end

  defp pull_set(:cvss_v4, children, case_record, opts) do
    case children.metrics do
      [] -> :ok
      [%{cvss_v4: vector}] -> vector |> Apply.put_general_metric(case_record, opts) |> ok()
    end
  end

  defp pull_set(:weaknesses, children, case_record, opts) do
    present = MapSet.new(case_record.weaknesses, & &1.cwe_id)

    children.weaknesses
    |> Enum.reject(&MapSet.member?(present, &1.cwe_id))
    |> Apply.known_weaknesses()
    |> after_existing(case_record.weaknesses)
    |> Apply.each(&Apply.add_weakness(&1, case_record.id, opts))
  end

  defp pull_set(:credits, children, case_record, opts) do
    present = Map.new(case_record.credits, &{People.person_key(&1), &1})

    Apply.each(children.credits, fn credit ->
      case Map.fetch(present, People.person_key(credit)) do
        :error ->
          [row] = Apply.credit_rows([credit])
          Apply.add_credit(row, case_record.id, opts)

        {:ok, here} ->
          add_roles(here, credit.credit_types, opts)
      end
    end)
  end

  defp pull_set(:affected, children, case_record, opts) do
    children.affected
    |> Enum.reject(&Diff.package_present?(case_record, &1))
    |> Apply.each(&Apply.add_package(&1, case_record.id, opts))
  end

  defp add_roles(credit, roles, opts) do
    case roles -- credit.credit_types do
      [] ->
        {:ok, credit}

      _missing ->
        Cases.edit_case_credit(credit, %{credit_types: credit.credit_types ++ roles}, opts)
    end
  end

  defp ok({:ok, _metric}), do: :ok
  defp ok({:error, error}), do: {:error, error}

  defp after_existing(rows, existing) do
    rows
    |> Enum.with_index(length(existing))
    |> Enum.map(fn {row, position} -> %{row | position: position} end)
  end
end
