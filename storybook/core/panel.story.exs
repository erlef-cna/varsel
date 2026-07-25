# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Panel do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.panel/1

  def layout, do: :one_column

  # The sandbox centers its children; panels are block-level cards that lay
  # out against the full content width in the app.
  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :default,
        slots: [
          "<:title>Description</:title>",
          "<p class=\"text-sm\">A heap overflow in the packet parser allows a remote attacker to crash the node.</p>"
        ]
      },
      %Variation{
        id: :with_actions,
        description: "Actions sit right of the title, in normal case.",
        slots: [
          "<:title>Affected packages</:title>",
          """
          <:actions>
            <button class="link link-hover text-primary">Edit</button>
            <button class="link link-hover text-primary">Suggest</button>
          </:actions>
          """,
          "<p class=\"text-sm text-base-content/60\">No packages recorded yet.</p>"
        ]
      },
      %Variation{
        id: :editing,
        description: "`editing?` tints the border — the \"you are editing this card\" signal.",
        attributes: %{editing?: true},
        slots: [
          "<:title>Description</:title>",
          """
          <:actions><button class="link link-hover text-primary">Cancel</button></:actions>
          """,
          ~s(<textarea class="w-full textarea font-mono text-sm" rows="3">A heap overflow in the packet parser.</textarea>)
        ]
      },
      %Variation{
        id: :rich_title,
        description: "The title slot mixes mono and text runs.",
        slots: [
          """
          <:title>
            <span class="font-mono normal-case tracking-normal text-sm">rabbit_common</span>
            <span class="text-base-content/40">· hex</span>
          </:title>
          """,
          "<p class=\"text-sm\">3 version events across 2 release lines.</p>"
        ]
      }
    ]
  end
end
