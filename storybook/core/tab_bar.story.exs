# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.TabBar do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.tab_bar/1

  def layout, do: :one_column

  def variations do
    [
      %Variation{
        id: :default,
        description: "The first tab selected.",
        attributes: %{select: "preview_tab"},
        slots: [
          ~s|<:tab value="validation" active="validation">Validation</:tab>|,
          ~s|<:tab value="json" active="validation">Rendered JSON</:tab>|
        ]
      },
      %Variation{
        id: :later_tab,
        description: "The underline follows whichever value `active` names.",
        attributes: %{select: "preview_tab"},
        slots: [
          ~s|<:tab value="validation" active="json">Validation</:tab>|,
          ~s|<:tab value="json" active="json">Rendered JSON</:tab>|,
          ~s|<:tab value="diff" active="json">Diff to published</:tab>|
        ]
      },
      %Variation{
        id: :with_actions,
        description: "`actions` trails the tabs, pushed to the far end of the row.",
        attributes: %{select: "preview_tab"},
        slots: [
          ~s|<:tab value="validation" active="validation">Validation</:tab>|,
          ~s|<:tab value="json" active="validation">Rendered JSON</:tab>|,
          """
          <:actions>
            <button class="link link-hover pb-2 text-xs text-primary">Re-render</button>
          </:actions>
          """
        ]
      }
    ]
  end
end
