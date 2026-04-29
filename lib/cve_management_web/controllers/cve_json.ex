# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CveJSON do
  def index(%{records: records}) do
    Enum.map(records, &entry/1)
  end

  defp entry(r) do
    %{
      id: r.cve_id,
      title: r.title,
      datePublished: format_datetime(r.date_published),
      dateUpdated: format_datetime(r.date_updated),
      details: "/cves/#{r.cve_id}.json"
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(dt), do: DateTime.to_iso8601(dt)
end
