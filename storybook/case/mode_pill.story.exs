# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ModePill do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.mode_pill/1

  def variations do
    [
      %Variation{
        id: :off,
        description: "Suggest mode off — edits are applied directly.",
        attributes: %{on?: false}
      },
      %Variation{
        id: :on,
        description: "Suggest mode on — the band's toggle, filled.",
        attributes: %{on?: true}
      },
      %Variation{
        id: :on_explained,
        description: "`explain` adds the read-only rider shown above a card being edited.",
        attributes: %{on?: true, explain: true}
      },
      %Variation{
        id: :off_explained,
        description: "The rider is suppressed when the mode is off.",
        attributes: %{on?: false, explain: true}
      }
    ]
  end
end
