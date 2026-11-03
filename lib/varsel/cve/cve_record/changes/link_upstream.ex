# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Changes.LinkUpstream do
  @moduledoc """
  Looks up an upstream CVE ID at MITRE and fills the new record from it.

  An upstream CVE is one that another CNA assigned for code outside this
  CNA's scope, so an ID this CNA owns is refused: it belongs in the pool.
  """

  use Ash.Resource.Change

  alias Varsel.CVE.MitreCveApi

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, &link/1)
  end

  defp link(changeset) do
    cve_id = Ash.Changeset.get_argument(changeset, :cve_id)

    case lookup(cve_id) do
      {:ok, attributes} ->
        Ash.Changeset.force_change_attributes(
          changeset,
          Map.merge(attributes, %{state: :draft, upstream: true})
        )

      {:error, message} ->
        Ash.Changeset.add_error(changeset, field: :cve_id, message: message)
    end
  end

  defp lookup(cve_id) do
    case MitreCveApi.get_id(cve_id) do
      {:ok, %{"state" => "RESERVED"} = id_object} -> reserved(id_object)
      {:ok, %{"state" => "PUBLISHED"} = id_object} -> published(cve_id, id_object)
      {:ok, %{"state" => state}} -> {:error, "is #{state} at MITRE"}
      {:error, reason} -> {:error, "could not be looked up at MITRE: #{reason}"}
    end
  end

  defp reserved(%{"owning_cna" => owning_cna} = id_object) do
    if owning_cna == short_name() do
      {:error, own_id_message()}
    else
      {:ok, %{reservation_json: id_object}}
    end
  end

  defp published(cve_id, id_object) do
    with {:ok, cve_json} <- fetch_record(cve_id) do
      if id_object["owning_cna"] == short_name() or
           get_in(cve_json, ["cveMetadata", "assignerOrgId"]) ==
             Application.fetch_env!(:varsel, :cna_org_id) do
        {:error, own_id_message()}
      else
        {:ok, %{reservation_json: id_object, cve_json: cve_json, last_synced_at: DateTime.utc_now()}}
      end
    end
  end

  defp fetch_record(cve_id) do
    case MitreCveApi.get(cve_id) do
      {:ok, cve_json} -> {:ok, cve_json}
      {:error, reason} -> {:error, "could not be fetched from MITRE: #{reason}"}
    end
  end

  defp short_name, do: Application.get_env(:varsel, :cna_short_name, "EEF")

  defp own_id_message, do: "is assigned by this CNA; assign it from the pool instead"
end
