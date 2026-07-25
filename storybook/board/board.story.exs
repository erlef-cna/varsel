# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Board.Board do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.BoardComponents.board/1

  def layout, do: :one_column

  # The board lays its lanes across the page's full width.
  def container, do: {:div, class: "w-full"}

  defp lane(label, dot, count, cards) do
    """
    <VarselWeb.BoardComponents.lane
      label="#{label}"
      dot="#{dot}"
      count={#{count}}
      cards?={#{cards != []}}
    >
      #{Enum.join(cards, "\n")}
    </VarselWeb.BoardComponents.lane>
    """
  end

  defp card(title, score, ref) do
    """
    <VarselWeb.BoardComponents.card>
      <:title>#{title}</:title>
      <:chips><VarselWeb.CoreComponents.severity_chip score={#{score}} /></:chips>
      <:footer>
        <span class="font-mono text-[0.68rem] text-base-content/50">#{ref}</span>
        <span class="text-[0.68rem] whitespace-nowrap text-base-content/50">3 d</span>
      </:footer>
    </VarselWeb.BoardComponents.card>
    """
  end

  def variations do
    [
      %Variation{
        id: :pipeline,
        description:
          "The case pipeline: four lanes across, wrapping to one column on a narrow " <>
            "screen. An empty lane keeps its place, so the shape holds steady as work moves.",
        slots: [
          lane("Draft", "bg-warning", 2, [
            card("Heap overflow in the packet parser", 8.8, "CVE-2026-20013"),
            card("Path traversal in archive extraction", 5.3, "no CVE yet")
          ]),
          lane("Review", "bg-info", 1, [
            card("Improper certificate validation", 9.3, "no CVE yet")
          ]),
          lane("Approved", "bg-[color:var(--violet)]", 1, [
            card("Timing oracle in constant_time_compare", 2.3, "CVE-2026-20011")
          ]),
          lane("Publishing", "bg-info", 0, [])
        ]
      }
    ]
  end
end
