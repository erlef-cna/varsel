# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Changes.PutEnrichment do
  @moduledoc """
  Puts the `adp_container` argument into `cve_json` as this CNA's ADP
  container, as MITRE does when an ADP submits one: the container carries
  this CNA's `providerMetadata` and the update time, and the record's
  `cveMetadata.dateUpdated` advances with it.
  """

  use Ash.Resource.Change

  alias Varsel.CVE.OwnContainer

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    with %{} = cve_json <- Ash.Changeset.get_attribute(changeset, :cve_json),
         %{} = adp_container <- Ash.Changeset.get_argument(changeset, :adp_container) do
      now = DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()

      adp_container =
        Map.put(
          adp_container,
          "providerMetadata",
          Map.put(OwnContainer.provider_metadata(), "dateUpdated", now)
        )

      cve_json =
        cve_json
        |> OwnContainer.put(adp_container)
        |> put_in(["cveMetadata", "dateUpdated"], now)

      Ash.Changeset.force_change_attribute(changeset, :cve_json, cve_json)
    else
      _missing -> changeset
    end
  end
end
