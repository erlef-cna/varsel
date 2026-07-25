# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.EditActions do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.edit_actions/1

  def layout, do: :one_column

  def description, do: "The row that closes an edit: commit, abandon, and why."

  def variations do
    [
      %Variation{
        id: :edit,
        description: "Editing directly — the change lands on the case.",
        attributes: %{mode: :edit, cancel: "cancel_edit"}
      },
      %Variation{
        id: :propose,
        description:
          "Suggesting instead — the commit restyles, and the reasoning that rides " <>
            "along with the suggestion appears.",
        attributes: %{mode: :propose, cancel: "cancel_edit"}
      }
    ]
  end
end
