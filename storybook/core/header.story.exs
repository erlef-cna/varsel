# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Header do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.header/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :default,
        slots: ["API tokens"]
      },
      %Variation{
        id: :with_subtitle,
        slots: [
          "API tokens",
          "<:subtitle>Personal access tokens for the GraphQL and MCP endpoints.</:subtitle>"
        ]
      },
      %Variation{
        id: :with_actions,
        description: "Actions switch the header to a spaced row.",
        slots: [
          "API tokens",
          "<:subtitle>Personal access tokens.</:subtitle>",
          ~s|<:actions><button class="btn btn-primary btn-sm">New token</button></:actions>|
        ]
      }
    ]
  end
end
