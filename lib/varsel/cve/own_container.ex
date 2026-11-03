# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.OwnContainer do
  @moduledoc """
  The container this CNA authored in a CVE record.

  In a record this CNA assigned, that is the CNA container. In an upstream
  record, which another CNA assigned, it is the ADP container with this
  CNA's `orgId`.
  """

  @doc "The record's `assignerOrgId` names another CNA."
  @spec upstream?(map()) :: boolean()
  def upstream?(cve_json) do
    case get_in(cve_json, ["cveMetadata", "assignerOrgId"]) do
      org_id when is_binary(org_id) -> org_id != org_id()
      _missing -> false
    end
  end

  @doc "This CNA's container in the record, or nil."
  @spec get(map()) :: map() | nil
  def get(cve_json) do
    if upstream?(cve_json) do
      cve_json |> adp_entries() |> Enum.find(&own?/1)
    else
      get_in(cve_json, ["containers", "cna"])
    end
  end

  @doc "Puts `container` into the record as this CNA's container."
  @spec put(map(), map()) :: map()
  def put(cve_json, container) do
    containers = Map.get(cve_json, "containers", %{})

    containers =
      if upstream?(cve_json) do
        Map.put(containers, "adp", Enum.reject(adp_entries(cve_json), &own?/1) ++ [container])
      else
        Map.put(containers, "cna", container)
      end

    Map.put(cve_json, "containers", containers)
  end

  @doc "This CNA's `providerMetadata`."
  @spec provider_metadata() :: map()
  def provider_metadata do
    %{"orgId" => org_id(), "shortName" => Application.get_env(:varsel, :cna_short_name, "EEF")}
  end

  @doc "This CNA's MITRE org ID."
  @spec org_id() :: String.t()
  def org_id, do: Application.fetch_env!(:varsel, :cna_org_id)

  defp adp_entries(cve_json), do: get_in(cve_json, ["containers", "adp"]) || []

  defp own?(container), do: get_in(container, ["providerMetadata", "orgId"]) == org_id()
end
