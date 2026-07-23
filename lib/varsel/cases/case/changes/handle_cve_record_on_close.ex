# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.HandleCveRecordOnClose do
  @moduledoc """
  Closing a case that already has a CVE ID assigned forces an explicit
  decision — an assigned (drafted) ID cannot silently return to the pool:

  * `reject_cve_id: true` — rejects the ID at MITRE (burns it) via
    `Varsel.CVE.CveRecord.:reject`.
  * `acknowledge_parked_cve_id: true` — keeps the ID parked in its current
    state at MITRE.
  * neither — the close is refused.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      reject? = Ash.Changeset.get_argument(changeset, :reject_cve_id)
      acknowledge? = Ash.Changeset.get_argument(changeset, :acknowledge_parked_cve_id)

      case {changeset.data.cve_record_id, reject?, acknowledge?} do
        {nil, _, _} ->
          changeset

        {_id, true, _} ->
          reject_cve_record(changeset, context.actor)

        {_id, _, true} ->
          changeset

        {_id, false, false} ->
          Ash.Changeset.add_error(changeset,
            field: :reject_cve_id,
            message:
              "a CVE ID is assigned to this case; pass reject_cve_id: true to burn it " <>
                "or acknowledge_parked_cve_id: true to keep it parked"
          )
      end
    end)
  end

  defp reject_cve_record(changeset, actor) do
    reason = Ash.Changeset.get_attribute(changeset, :closed_reason) || "Case closed"
    cve_record = Varsel.CVE.get_cve_record!(changeset.data.cve_record_id, authorize?: false)

    case cve_record
         |> Ash.Changeset.for_update(:reject, %{rejection_reason: reason}, actor: actor)
         |> Ash.update() do
      {:ok, _} -> changeset
      {:error, error} -> Ash.Changeset.add_error(changeset, error)
    end
  end
end
