# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.AssignCveRecord do
  @moduledoc """
  Assigns a CVE ID to the case: takes the given (or the lowest free) reserved
  `Varsel.CVE.CveRecord` out of the open pool via its `:assign` transition and
  links it to the case.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      cond do
        changeset.data.state == :published ->
          Ash.Changeset.add_error(changeset,
            field: :cve_record_id,
            message: "the case is already published"
          )

        changeset.data.cve_record_id ->
          Ash.Changeset.add_error(changeset,
            field: :cve_record_id,
            message: "the case already has a CVE ID assigned"
          )

        true ->
          assign(changeset, context.actor)
      end
    end)
  end

  defp assign(changeset, actor) do
    with {:ok, reserved} <- pick_record(Ash.Changeset.get_argument(changeset, :cve_record_id)),
         {:ok, assigned} <-
           reserved
           |> Ash.Changeset.for_update(:assign, %{}, actor: actor)
           |> Ash.update() do
      Ash.Changeset.force_change_attribute(changeset, :cve_record_id, assigned.id)
    else
      {:error, error} -> Ash.Changeset.add_error(changeset, error)
    end
  end

  defp pick_record(nil) do
    year = Date.utc_today().year

    case year
         |> Varsel.CVE.query_to_available_cve_records(authorize?: false)
         |> Ash.Query.load(:cve_id)
         |> Ash.read!(authorize?: false)
         |> Enum.sort_by(&cve_number/1)
         |> List.first() do
      nil -> {:error, "no reserved CVE IDs available in the #{year} pool"}
      record -> {:ok, record}
    end
  end

  defp pick_record(cve_record_id) do
    case Varsel.CVE.get_cve_record(cve_record_id, authorize?: false) do
      {:ok, %{state: :reserved} = record} -> {:ok, record}
      {:ok, %{state: state}} -> {:error, "CVE record is #{state}, not reserved"}
      {:error, _} -> {:error, "CVE record does not exist"}
    end
  end

  # Numeric sort: "CVE-2026-123" comes before "CVE-2026-1024".
  defp cve_number(%{cve_id: cve_id}) do
    cve_id |> String.split("-") |> List.last() |> String.to_integer()
  end
end
