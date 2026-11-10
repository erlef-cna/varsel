# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.SuggestToggle do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.suggest_toggle/1

  def variations do
    [
      %Variation{
        id: :off,
        description: "Edits apply directly.",
        attributes: %{on?: false}
      },
      %Variation{
        id: :on,
        description: "Edits become suggestions by choice.",
        attributes: %{on?: true}
      },
      %Variation{
        id: :forced,
        description: "A frozen case locks the switch on.",
        attributes: %{on?: true, forced?: true}
      }
    ]
  end
end
