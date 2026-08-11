# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.AssignCveRecord do
  @moduledoc """
  Assigns a CVE ID to the case: takes the given (or the lowest free) reserved
  `Varsel.CVE.CveRecord` out of the open pool via its `:assign` transition and
  links it to the case.

  Reading the pool and transitioning a record are POC-only on
  `Varsel.CVE.CveRecord`, while `:assign_cve_id` also admits an assigned
  supporter — bounded there to the *next free* ID, since naming a record is
  forbidden to anyone but a POC. The steps below therefore run unauthorized by
  design: `:assign_cve_id`'s own policy is the whole of the boundary, and
  nothing a caller supplies reaches these calls. A supporter still cannot read
  the pool or transition a record by asking `CveRecord` directly.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, &assign(&1, context.actor))
  end

  defp assign(changeset, actor) do
    with {:ok, reserved} <-
           pick_record(Ash.Changeset.get_argument(changeset, :cve_record_id), actor),
         {:ok, assigned} <-
           reserved
           # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
           |> Ash.Changeset.for_update(:assign, %{}, actor: actor, authorize?: false)
           |> Ash.update() do
      Ash.Changeset.force_change_attribute(changeset, :cve_record_id, assigned.id)
    else
      {:error, error} -> Ash.Changeset.add_error(changeset, error)
    end
  end

  defp pick_record(nil, actor) do
    year = Date.utc_today().year

    year
    |> Varsel.CVE.query_to_available_cve_records()
    |> Ash.Query.load(:cve_id)
    # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
    |> Ash.read!(actor: actor, authorize?: false)
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
  defp pick_record(cve_record_id, actor) do
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
