# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.StatTiles do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.stat_tiles/1

  def layout, do: :one_column

  # The tile row is a full-width auto-fit grid.
  def container, do: {:div, class: "w-full"}

  defp case_options do
    [
      %{value: "all", label: "All", count: 128},
      %{value: "draft", label: "Draft", count: 41, dot: "bg-base-content/30"},
      %{value: "review", label: "Review", count: 12, dot: "bg-info"},
      %{value: "approved", label: "Approved", count: 5, dot: "bg-[color:var(--violet)]"},
      %{value: "published", label: "Published", count: 70, dot: "bg-success"}
    ]
  end

  def variations do
    [
      %Variation{
        id: :default,
        description: "The console's queue board. Overview and filter are one control.",
        attributes: %{active: "all", options: case_options()}
      },
      %Variation{
        id: :filtered,
        description: "The active tile carries the primary tint.",
        attributes: %{active: "review", options: case_options()}
      },
      %Variation{
        id: :without_dots,
        description: "`:dot` is optional — tiles render as plain counts.",
        attributes: %{
          active: "open",
          options: [
            %{value: "open", label: "Open reports", count: 7},
            %{value: "triaged", label: "Triaged", count: 23},
            %{value: "rejected", label: "Rejected", count: 4}
          ]
        }
      },
      %Variation{
        id: :empty_queue,
        description: "Zero counts still render — an empty queue is information.",
        attributes: %{
          active: "all",
          options: [
            %{value: "all", label: "All", count: 0},
            %{value: "draft", label: "Draft", count: 0, dot: "bg-base-content/30"},
            %{value: "review", label: "Review", count: 0, dot: "bg-info"}
          ]
        }
      },
      %Variation{
        id: :long_labels,
        description: "Labels truncate rather than wrapping the tile.",
        attributes: %{
          active: "pending",
          options: [
            %{
              value: "pending",
              label: "Pending maintainer response",
              count: 3,
              dot: "bg-warning"
            },
            %{value: "awaiting", label: "Awaiting MITRE publication", count: 1, dot: "bg-info"}
          ]
        }
      }
    ]
  end
end
