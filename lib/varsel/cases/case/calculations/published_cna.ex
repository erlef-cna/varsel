# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.PublishedCna do
  @moduledoc """
  The CNA container currently published on the case's CVE record (nil when the
  case was never published), for diffing against a fresh `:preview` render.

  Loading this calculation is gated by the case read policy, and it declares its
  own `:cve_record` load, so the published data is read through the authorized
  path rather than a bypass.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [cve_record: [:cve_json]]

  @impl Calculation
  def calculate(records, _opts, _context), do: Enum.map(records, &published_cna/1)

  # `providerMetadata.dateUpdated` is stripped — MITRE stamps it on every push,
  # so it would be pure diff noise against a fresh preview.
  defp published_cna(case_record) do
    with %{cve_record: %{cve_json: cve_json}} when is_map(cve_json) <- case_record,
         %{} = cna <- get_in(cve_json, ["containers", "cna"]) do
      case cna do
        %{"providerMetadata" => %{} = provider} ->
          Map.put(cna, "providerMetadata", Map.delete(provider, "dateUpdated"))

        _no_provider_metadata ->
          cna
      end
    else
      _never_published -> nil
    end
  end
end
