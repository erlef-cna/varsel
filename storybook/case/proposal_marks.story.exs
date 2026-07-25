# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ProposalMarks do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.proposal_marks/1

  def layout, do: :one_column

  def description, do: "What a row's open suggestions have made of it."

  def variations do
    [
      %Variation{
        id: :phantom,
        description: "A row only a suggestion puts there.",
        attributes: %{
          row_id: "row-1",
          marks: marks(phantom: ["row-1"])
        }
      },
      %Variation{
        id: :deleted,
        description: "A row a suggestion would take away.",
        attributes: %{
          row_id: "row-1",
          marks: marks(deleted: ["row-1"])
        }
      },
      %Variation{
        id: :untouched,
        description: "A row no suggestion touches says nothing.",
        attributes: %{row_id: "row-1", marks: marks([])}
      }
    ]
  end

  defp marks(opts) do
    %{
      phantom: MapSet.new(Keyword.get(opts, :phantom, [])),
      deleted: MapSet.new(Keyword.get(opts, :deleted, []))
    }
  end
end
