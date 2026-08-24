# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.AssignCveRecord do
  @moduledoc """
  Assigns a CVE ID to the case: takes the given (or the lowest free) reserved
  `Varsel.CVE.CveRecord` out of the open pool via its `:assign` transition and
  links it to the case.

  The pool read and the `:assign` transition carry the stamp the `CveRecord`
  policies demand, so an assigned supporter passes them only through this
  change. `:assign_cve_id` bounds a supporter to the *next free* ID; naming a
  record stays a POC decision.
  """

  use Ash.Resource.Change

  @stamp %{private: %{assign_cve_id?: true}}

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, &assign(&1, context))
  end

  defp assign(changeset, context) do
    opts =
      context
      |> Ash.Context.to_opts()
      |> Keyword.update(:context, @stamp, &Ash.Helpers.deep_merge_maps(&1, @stamp))

    with {:ok, reserved} <-
           pick_record(Ash.Changeset.get_argument(changeset, :cve_record_id), opts, context.actor),
         {:ok, assigned} <-
           reserved
           |> Ash.Changeset.for_update(:assign, %{}, opts)
           |> Ash.update() do
      Ash.Changeset.force_change_attribute(changeset, :cve_record_id, assigned.id)
    else
      {:error, error} -> Ash.Changeset.add_error(changeset, error)
    end
  end

  defp pick_record(nil, opts, _actor) do
    year = Date.utc_today().year

    year
    |> Varsel.CVE.query_to_available_cve_records()
    |> Ash.Query.load(:cve_id)
    |> Ash.read!(opts)
    |> Enum.sort_by(&cve_number/1)
    |> List.first()
    |> case do
      nil -> {:error, "no reserved CVE IDs available in the #{year} pool"}
      record -> {:ok, record}
    end
  end

  # Naming an ID explicitly also reaches withheld ones: the auto-pick above
  # never offers them (:available is reserved-only), but someone who types the
  # ID of an ID they are holding has said what they mean. Only a POC reaches
  # this clause — `:assign_cve_id` forbids anyone else naming a record — so the
  # read stays authorized as that POC.
  defp pick_record(cve_record_id, _opts, actor) do
    case Varsel.CVE.get_cve_record(cve_record_id, actor: actor) do
      {:ok, %{state: state} = record} when state in [:reserved, :withheld] -> {:ok, record}
      {:ok, %{state: state}} -> {:error, "CVE record is #{state}, not reserved"}
      {:error, _} -> {:error, "CVE record does not exist"}
    end
  end

  # Numeric sort: "CVE-2026-123" comes before "CVE-2026-1024".
  defp cve_number(%{cve_id: cve_id}) do
    cve_id |> String.split("-") |> List.last() |> String.to_integer()
  end
end
