# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.JumpPagination do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.jump_pagination/1

  def layout, do: :one_column

  # The list card's footer row — full width, with its own top border.
  def container, do: {:div, class: "w-full"}

  defp page(offset, count, limit \\ 20) do
    %Ash.Page.Offset{
      results: [],
      limit: limit,
      offset: offset,
      count: count,
      more?: offset + limit < count
    }
  end

  def variations do
    [
      %Variation{
        id: :first_page,
        attributes: %{page: page(0, 128)}
      },
      %Variation{
        id: :middle_page,
        description: "Typing a page number and pressing Enter pushes `jump_event`.",
        attributes: %{page: page(60, 128)}
      },
      %Variation{
        id: :last_page,
        attributes: %{page: page(120, 128)}
      },
      %Variation{
        id: :single_result,
        description: "The noun is singular at a count of one.",
        attributes: %{page: page(0, 1)}
      },
      %Variation{
        id: :custom_noun,
        description: "`noun` is pluralised with a trailing \"s\".",
        attributes: %{page: page(0, 43), noun: "report"}
      },
      %Variation{
        id: :no_results,
        description: "Zero results render nothing — callers show an empty state instead.",
        attributes: %{page: page(0, 0)}
      }
    ]
  end
end
