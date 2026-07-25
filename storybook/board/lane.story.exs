# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Board.Lane do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.BoardComponents.lane/1

  def layout, do: :one_column

  # A lane is one column of the board's row.
  def container, do: {:div, class: "w-64"}

  defp card(title, chips, footer) do
    """
    <VarselWeb.BoardComponents.card>
      <:title>#{title}</:title>
      <:chips>#{chips}</:chips>
      <:footer>
        <span class="font-mono text-[0.68rem] text-base-content/50">#{footer}</span>
        <span class="text-[0.68rem] whitespace-nowrap text-base-content/50">3 d</span>
      </:footer>
    </VarselWeb.BoardComponents.card>
    """
  end

  defp severity(score) do
    ~s(<VarselWeb.CoreComponents.severity_chip score={#{score}} />)
  end

  def variations do
    [
      %Variation{
        id: :with_cards,
        description: "The dot and the count say which state the lane stands for, and how full.",
        attributes: %{label: "Draft", dot: "bg-warning", count: 2},
        slots: [
          card("Heap overflow in the packet parser", severity(8.8), "CVE-2026-20013"),
          card("Path traversal in archive extraction", severity(5.3), "no CVE yet")
        ]
      },
      %Variation{
        id: :empty,
        description:
          "A lane with nothing in it keeps its place in the row; the dash holds the " <>
            "space a card would take.",
        attributes: %{label: "Publishing", dot: "bg-info", count: 0, cards?: false, quiet?: true},
        slots: [""]
      },
      %Variation{
        id: :clipped,
        description:
          "A lane showing only part of its cards puts the control for the rest in " <>
            "`footer` — the page owns the control and what it does.",
        attributes: %{label: "Review", dot: "bg-info", count: 12},
        slots: [
          card("Improper certificate validation", severity(9.3), "CVE-2026-20015"),
          card("Timing oracle in constant_time_compare", severity(2.3), "no CVE yet"),
          """
          <:footer>
            <button type="button" class="w-full py-2 cursor-pointer">Show all 12 ▾</button>
          </:footer>
          """
        ]
      },
      %VariationGroup{
        id: :states,
        description: "The four states a case moves through, each with its own dot.",
        variations: [
          %Variation{
            id: :draft,
            attributes: %{label: "Draft", dot: "bg-warning", count: 12, cards?: false},
            slots: [""]
          },
          %Variation{
            id: :review,
            attributes: %{label: "Review", dot: "bg-info", count: 3, cards?: false},
            slots: [""]
          },
          %Variation{
            id: :approved,
            attributes: %{
              label: "Approved",
              dot: "bg-[color:var(--violet)]",
              count: 1,
              cards?: false
            },
            slots: [""]
          },
          %Variation{
            id: :publishing,
            attributes: %{label: "Publishing", dot: "bg-info", count: 0, cards?: false},
            slots: [""]
          }
        ]
      }
    ]
  end
end
