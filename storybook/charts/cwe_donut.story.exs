# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Charts.CweDonut do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  alias VarselWeb.Charts

  def function, do: &VarselWeb.ChartComponents.cwe_donut/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-[340px]"}

  # Static sample entries: id/name/count/href maps, no DB involved.
  defp entries(entries, center_total \\ nil) do
    dist = %{entries: entries}
    dist = if center_total, do: Map.put(dist, :center_total, center_total), else: dist
    Charts.donut_geometry(dist)
  end

  def variations do
    [
      %Variation{
        id: :view_root,
        description: "Declared members of a view, linking to their drill-down pages.",
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
        description: "A member with no matching CVEs still renders — invisible arc, still linked.",
        attributes: %{
          data:
            entries([
              %{id: "CWE-707", name: "Improper Neutralization", count: 10, href: "#/1000/707"},
              %{id: "CWE-284", name: "Improper Access Control", count: 0, href: "#/1000/284"}
            ])
        }
      },
      %Variation{
        id: :single_full_ring,
        description: "One entry holding 100% of the total renders a full ring, not a degenerate arc.",
        attributes: %{
          data: entries([%{id: "CWE-79", name: "Cross-site Scripting", count: 7, href: "#/1000/79"}])
        }
      },
      %Variation{
        id: :no_data,
        description:
          "No entries at all — an empty view or a leaf with no children. Renders a single greyed ring, not a broken chart.",
        attributes: %{data: entries([])}
      },
      %Variation{
        id: :all_zero_count,
        description:
          "Entries exist but every one counts 0 — same greyed-ring treatment as no entries at all (dividing by a zero total can't produce meaningful sweeps).",
        attributes: %{
          data:
            entries([
              %{id: "CWE-707", name: "Improper Neutralization", count: 0, href: "#/1000/707"},
              %{id: "CWE-284", name: "Improper Access Control", count: 0, href: "#/1000/284"}
            ])
        }
      },
      %Variation{
        id: :distinct_center_total,
        description:
          "The center shows the page's own recursive CVE total (87), not the slice-sum (60) — slices keep their own share of the slice-sum.",
        attributes: %{
          data:
            entries(
              [
                %{id: "CWE-707", name: "Improper Neutralization", count: 42, href: "#/1000/707"},
                %{id: "CWE-284", name: "Improper Access Control", count: 18, href: "#/1000/284"}
              ],
              87
            )
        }
      }
    ]
  end
end
