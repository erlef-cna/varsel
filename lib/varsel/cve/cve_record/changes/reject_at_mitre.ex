# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Changes.RejectAtMitre do
  @moduledoc """
  Rejects the CVE ID at MITRE before the row moves to `:rejected`.

  MITRE is called first, so a refusal aborts the transition and the row keeps
  its current state.
  """

  use Ash.Resource.Change

  alias Varsel.CVE.MitreCveApi

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      case MitreCveApi.reject(cve_id(changeset.data)) do
        {:ok, _} -> changeset
        {:error, reason} -> Ash.Changeset.add_error(changeset, reason)
      end
    end)
  end

  # A bulk reject selects rows without loading the calculated cve_id, so it
  # falls back to the JSON the row already carries.
  defp cve_id(%{cve_id: %Ash.NotLoaded{}} = data) do
    get_in(data.cve_json || %{}, ["cveMetadata", "cveId"]) ||
      get_in(data.reservation_json || %{}, ["cve_id"])
  end

  defp cve_id(%{cve_id: cve_id}), do: cve_id
end
