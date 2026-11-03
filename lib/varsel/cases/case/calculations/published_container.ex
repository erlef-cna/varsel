# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.PublishedContainer do
  @moduledoc """
  The container this CNA currently publishes on the case's CVE record (nil
  when the case was never published), for diffing against a fresh `:preview`
  render. See `Varsel.CVE.OwnContainer`.

  Loading this calculation is gated by the case read policy, and it declares its
  own `:cve_record` load, so the published data is read through the authorized
  path rather than a bypass.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation
  alias Varsel.CVE.OwnContainer

  @impl Calculation
  def load(_query, _opts, _context), do: [cve_record: [:cve_json]]

  @impl Calculation
  def calculate(records, _opts, _context), do: Enum.map(records, &published_container/1)

  # `providerMetadata.dateUpdated` is stripped. It is stamped on every
  # publish, so it would be pure diff noise against a fresh preview.
  defp published_container(%{cve_record: %{cve_json: %{} = cve_json}}) do
    case OwnContainer.get(cve_json) do
      %{"providerMetadata" => %{} = provider} = container ->
        Map.put(container, "providerMetadata", Map.delete(provider, "dateUpdated"))

      container ->
        container
    end
  end

  defp published_container(_never_published), do: nil
end
