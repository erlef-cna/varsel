# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Board.Card do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.BoardComponents.card/1

  def layout, do: :one_column

  # Cards fill the width of the cell they sit in.
  def container, do: {:div, class: "w-64"}

  def variations do
    [
      %Variation{
        id: :title_only,
        description: "The least a card can carry.",
        slots: ["<:title>Denial of service in the packet parser</:title>"]
      },
      %Variation{
        id: :long_title,
        description: "A title runs to two lines, then cuts off.",
        slots: [
          "<:title>Unbounded request body accumulation on streaming RPCs causes memory exhaustion in the server under sustained load</:title>"
        ]
      },
      %Variation{
        id: :with_meta,
        description: "The line of marks: severity, what the card refers to, how long it has sat there.",
        slots: [
          "<:title>Path traversal in archive extraction</:title>",
          """
          <:meta>
            <VarselWeb.CoreComponents.severity_chip score={5.3} />
            <span class="font-mono text-[0.68rem] text-base-content/50">CVE-2026-20011</span>
            <span class="ml-auto text-[0.68rem] whitespace-nowrap text-base-content/50">3 d</span>
          </:meta>
          """
        ]
      },
      %Variation{
        id: :stale,
        description:
          "A card that has sat too long for the stage it is in names the stage in its age, " <>
            "and warms the tone.",
        slots: [
          "<:title>SSH_FXP_REALPATH path-existence oracle</:title>",
          """
          <:meta>
            <VarselWeb.CoreComponents.severity_chip score={2.3} />
            <span class="ml-auto text-[0.68rem] whitespace-nowrap text-warning">9 d in review</span>
          </:meta>
          """
        ]
      },
      %Variation{
        id: :unclaimed,
        description: "Nobody has picked this one up.",
        slots: [
          "<:title>Improper certificate validation</:title>",
          """
          <:meta>
            <VarselWeb.CoreComponents.severity_chip score={9.3} />
            <span class="ml-auto flex items-center gap-1.5">
              <span class="text-[0.68rem] whitespace-nowrap text-base-content/50">1 d</span>
              <VarselWeb.BoardComponents.unclaimed_disc />
            </span>
          </:meta>
          """
        ]
      }
    ]
  end
end
