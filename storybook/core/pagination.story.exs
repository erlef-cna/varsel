# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Pagination do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.pagination/1

  def layout, do: :one_column

  # The list card's footer row — full width, with its own top border.
  def container, do: {:div, class: "w-full"}

  def step_path("prev"), do: "?offset=40"
  def step_path("next"), do: "?offset=80"

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
        id: :link_mode,
        description:
          "With `patch`, prev/next render as real patch-link anchors — crawlable, " <>
            "and openable in a new tab — while the jump input keeps its event.",
        attributes: %{page: page(60, 128), patch: &__MODULE__.step_path/1}
      },
      %Variation{
        id: :last_page,
        attributes: %{page: page(120, 128)}
      },
      %VariationGroup{
        id: :single_page,
        description:
          "A list that fits on one page has nowhere to page to, so it keeps only its " <>
            "total — the page size and the controls would answer a question nobody asked.",
        variations: [
          %Variation{id: :one_result, attributes: %{page: page(0, 1)}},
          %Variation{id: :some_results, attributes: %{page: page(0, 12)}},
          %Variation{id: :exactly_full, attributes: %{page: page(0, 20)}}
        ]
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
