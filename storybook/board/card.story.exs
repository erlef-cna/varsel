# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Board.Card do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.BoardComponents.card/1

  def layout, do: :one_column

  # Cards fill the width of the lane they sit in.
  def container, do: {:div, class: "w-64"}

  def variations do
    [
      %Variation{
        id: :title_only,
        description: "The least a card can carry.",
        slots: ["<:title>Denial of service in the packet parser</:title>"]
      },
      %Variation{
        id: :with_chips,
        description:
          "`chips` mark the card at a glance — the case board puts severity and the " <>
            "packages a case touches here.",
        slots: [
          "<:title>Heap overflow in the TLS handshake</:title>",
          """
          <:chips>
            <VarselWeb.CoreComponents.severity_chip score={8.8} />
            <VarselWeb.BoardComponents.card_chip>otp</VarselWeb.BoardComponents.card_chip>
            <VarselWeb.BoardComponents.card_chip>ssl</VarselWeb.BoardComponents.card_chip>
          </:chips>
          """
        ]
      },
      %Variation{
        id: :with_footer,
        description: "The quiet line: what the card refers to, and how long it has sat there.",
        slots: [
          "<:title>Path traversal in archive extraction</:title>",
          """
          <:chips>
            <VarselWeb.CoreComponents.severity_chip score={5.3} />
            <VarselWeb.BoardComponents.card_chip>mpp</VarselWeb.BoardComponents.card_chip>
          </:chips>
          """,
          """
          <:footer>
            <span class="font-mono text-[0.68rem] text-base-content/50">CVE-2026-20011</span>
            <span class="text-[0.68rem] whitespace-nowrap text-base-content/50">3 d</span>
          </:footer>
          """
        ]
      },
      %Variation{
        id: :stale,
        description:
          "A card that has sat too long for the lane it is in names the lane in its age, " <>
            "and warms the tone.",
        slots: [
          "<:title>SSH_FXP_REALPATH path-existence oracle</:title>",
          """
          <:chips>
            <VarselWeb.CoreComponents.severity_chip score={2.3} />
          </:chips>
          """,
          """
          <:footer>
            <span class="font-mono text-[0.68rem] text-base-content/50">no CVE yet</span>
            <span class="text-[0.68rem] whitespace-nowrap text-warning">9 d in review</span>
          </:footer>
          """
        ]
      },
      %Variation{
        id: :unclaimed,
        description: "Nobody has picked this one up.",
        slots: [
          "<:title>Improper certificate validation</:title>",
          """
          <:footer>
            <span class="font-mono text-[0.68rem] text-base-content/50">no CVE yet</span>
            <span class="flex items-center gap-1.5">
              <span class="text-[0.68rem] whitespace-nowrap text-base-content/50">1 d</span>
              <VarselWeb.BoardComponents.unclaimed_disc />
            </span>
          </:footer>
          """
        ]
      }
    ]
  end
end
