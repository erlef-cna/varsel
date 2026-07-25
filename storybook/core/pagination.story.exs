# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Pagination do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.pagination/1

  def layout, do: :one_column

  # Both pagers take an `Ash.Page.Offset`; only offset/limit/count/more? are read.
  defp page(offset, count, opts \\ []) do
    %Ash.Page.Offset{
      results: [],
      limit: Keyword.get(opts, :limit, 20),
      offset: offset,
      count: count,
      more?: offset + Keyword.get(opts, :limit, 20) < count
    }
  end

  def variations do
    [
      %Variation{
        id: :first_page,
        description: "Previous is disabled on the first page.",
        attributes: %{page: page(0, 128)}
      },
      %Variation{
        id: :middle_page,
        attributes: %{page: page(60, 128)}
      },
      %Variation{
        id: :last_page,
        description: "Next is disabled on the last page.",
        attributes: %{page: page(120, 128)}
      },
      %Variation{
        id: :single_page,
        description: "A single page of results renders nothing at all.",
        attributes: %{page: page(0, 12)}
      }
    ]
  end
end
