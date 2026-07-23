# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Changes.PushUpdate do
  @moduledoc """
  Pushes the CNA container of an already-published record back to MITRE and
  re-syncs the full record. Idempotent: a record already in `:published`
  (because a concurrent job won the race) is a no-op.
  """

  use Ash.Resource.Change

  alias Varsel.CVE.MitreCveApi

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    record = changeset.data

    if record.state == :published do
      changeset
    else
      cve_id = get_in(record.cve_json, ["cveMetadata", "cveId"])
      cna_container = record.cve_json |> Map.get("containers", %{}) |> Map.get("cna", %{})

      with {:ok, _} <- MitreCveApi.update_cna(cve_id, cna_container),
           {:ok, full_record} <- MitreCveApi.get(cve_id) do
        changeset
        |> Ash.Changeset.force_change_attribute(:cve_json, full_record)
        |> Ash.Changeset.force_change_attribute(:last_synced_at, DateTime.utc_now())
        |> AshStateMachine.transition_state(:published)
      else
        {:error, reason} -> Ash.Changeset.add_error(changeset, reason)
      end
    end
  end
end
