# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.EditModeNotice do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.edit_mode_notice/1

  def layout, do: :one_column

  def description, do: "The rider above an open editor while suggesting."

  def variations do
    [
      %Variation{
        id: :propose,
        description: "Says the edits will become suggestions.",
        attributes: %{mode: :propose}
      },
      %Variation{
        id: :edit,
        description: "Renders nothing outside propose mode.",
        attributes: %{mode: :edit}
      }
    ]
  end
end
