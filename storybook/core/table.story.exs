# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Table do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.table/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  defp rows do
    [
      %{id: "1", cve: "CVE-2026-1234", package: "rabbit_common", state: "Published", score: 9.1},
      %{id: "2", cve: "CVE-2026-1235", package: "cowboy", state: "Review", score: 5.4},
      %{id: "3", cve: "CVE-2026-1236", package: "plug", state: "Draft", score: nil}
    ]
  end

  def variations do
    [
      %Variation{
        id: :default,
        attributes: %{id: "cves", rows: rows()},
        slots: [
          ~s|<:col :let={row} label="CVE"><span class="font-mono">{row.cve}</span></:col>|,
          ~s|<:col :let={row} label="Package">{row.package}</:col>|,
          ~s|<:col :let={row} label="State">{row.state}</:col>|
        ]
      },
      %Variation{
        id: :with_actions,
        description: "The `:action` slot adds a trailing, width-collapsed column.",
        attributes: %{id: "cves-actions", rows: rows()},
        slots: [
          ~s|<:col :let={row} label="CVE"><span class="font-mono">{row.cve}</span></:col>|,
          ~s|<:col :let={row} label="Package">{row.package}</:col>|,
          """
          <:action :let={row}>
            <a class="link link-hover text-primary" href={"/cases/" <> row.id}>Open</a>
          </:action>
          """,
          ~s|<:action><button class="link link-hover text-primary">Edit</button></:action>|
        ]
      },
      %Variation{
        id: :clickable_rows,
        description: "`row_click` makes the data cells clickable (cursor changes on hover).",
        attributes: %{
          id: "cves-clickable",
          rows: rows(),
          row_click: {:eval, ~s|fn row -> JS.navigate("/cases/" <> row.id) end|}
        },
        slots: [
          ~s|<:col :let={row} label="CVE"><span class="font-mono">{row.cve}</span></:col>|,
          ~s|<:col :let={row} label="State">{row.state}</:col>|
        ]
      },
      %Variation{
        id: :empty,
        description: "No rows — the header stays, so the table keeps its shape.",
        attributes: %{id: "cves-empty", rows: []},
        slots: [
          ~s|<:col :let={row} label="CVE">{row.cve}</:col>|,
          ~s|<:col :let={row} label="Package">{row.package}</:col>|
        ]
      }
    ]
  end
end
