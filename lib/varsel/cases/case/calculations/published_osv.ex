# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.PublishedOsv do
  @moduledoc """
  The OSV document currently published for the case's CVE record (nil when
  there is none), for diffing against a fresh `:preview` render.

  Loading this calculation is gated by the case read policy, and it declares
  its own `:cve_record` load, so the published data is read through the
  authorized path rather than a bypass.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [cve_record: [osv_record: [:osv_json]]]

  @impl Calculation
  def calculate(records, _opts, _context), do: Enum.map(records, &published_osv/1)

  # `modified` is stripped — the sync stamps it on every content change, so
  # it would be pure diff noise against a fresh preview.
  defp published_osv(%{cve_record: %{osv_record: %{osv_json: %{} = osv}}}), do: Map.delete(osv, "modified")

  defp published_osv(_never_published), do: nil
end
