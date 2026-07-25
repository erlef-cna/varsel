# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.RowActions do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.row_actions/1

  def layout, do: :one_column

  def description, do: "What can still be done to a row of a case."

  @untouched %{phantom: MapSet.new(), deleted: MapSet.new()}
  @proposed %{phantom: MapSet.new(["row-1"]), deleted: MapSet.new()}

  def variations do
    [
      %Variation{
        id: :edit,
        description: "Editing directly: the confirm asks plainly.",
        attributes: %{
          id: "row-1",
          type: "channel",
          noun: "channel",
          mode: :edit,
          marks: @untouched
        }
      },
      %Variation{
        id: :propose,
        description: "Suggesting: removal becomes something to propose.",
        attributes: %{
          id: "row-1",
          type: "channel",
          noun: "channel",
          mode: :propose,
          marks: @untouched
        }
      },
      %Variation{
        id: :caret,
        description: "The dense editor spells the way in as a caret.",
        attributes: %{
          id: "row-1",
          type: "channel",
          noun: "channel",
          mode: :edit,
          marks: @untouched,
          edit_label: "▸"
        }
      },
      %Variation{
        id: :already_proposed,
        description: "A row a suggestion already puts there offers nothing.",
        attributes: %{
          id: "row-1",
          type: "channel",
          noun: "channel",
          mode: :edit,
          marks: @proposed
        }
      },
      %Variation{
        id: :view,
        description: "A case being read rather than worked on offers nothing either.",
        attributes: %{
          id: "row-1",
          type: "channel",
          noun: "channel",
          mode: :view,
          marks: @untouched
        }
      }
    ]
  end
end
