# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Charts.CweLegend do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  alias VarselWeb.Charts

  def function, do: &VarselWeb.ChartComponents.cwe_legend/1

  def layout, do: :one_column

  def container, do: {:div, class: "max-w-md"}

  defp entries(entries), do: Charts.donut_geometry(%{entries: entries})

  def variations do
    [
      %Variation{
        id: :view_root,
        description: "Each row is a link (`display: table-row`) to its drill-down page.",
        attributes: %{
          data:
            entries([
              %{id: "CWE-707", name: "Improper Neutralization", count: 42, href: "#/1000/707"},
              %{id: "CWE-284", name: "Improper Access Control", count: 18, href: "#/1000/284"},
              %{
                id: "CWE-691",
                name: "Insufficient Control Flow Management",
                count: 5,
                href: "#/1000/691"
              }
            ])
        }
      },
      %Variation{
        id: :zero_count_member,
        description: "A zero-count row still links through — 0% is a valid destination.",
        attributes: %{
          data:
            entries([
              %{id: "CWE-707", name: "Improper Neutralization", count: 10, href: "#/1000/707"},
              %{id: "CWE-284", name: "Improper Access Control", count: 0, href: "#/1000/284"}
            ])
        }
      },
      %Variation{
        id: :no_data,
        attributes: %{data: entries([])}
      }
    ]
  end
end
