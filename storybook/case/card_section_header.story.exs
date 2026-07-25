# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CardSectionHeader do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.card_section_header/1

  def layout, do: :one_column

  def description, do: "The small heading above a part of a card."

  def variations do
    [
      %Variation{
        id: :section,
        description: "A section of the workspace, one step darker than what it holds.",
        attributes: %{title: "Affected", level: :h2}
      },
      %Variation{
        id: :subsection,
        description: "A part within a card.",
        attributes: %{title: "Boundary facts"}
      },
      %Variation{
        id: :with_action,
        description: "Whatever adds to the part sits along the same line.",
        attributes: %{title: "Channels"},
        slots: [
          """
          <:actions>
            <button class="btn btn-ghost btn-xs">Add channel</button>
          </:actions>
          """
        ]
      },
      %Variation{
        id: :with_menu,
        description: "The affected list adds through a menu of package kinds.",
        attributes: %{title: "Affected", level: :h2},
        slots: [
          """
          <:actions>
            <div class="link link-hover text-primary cursor-pointer text-xs">Add package ▾</div>
          </:actions>
          """
        ]
      }
    ]
  end
end
