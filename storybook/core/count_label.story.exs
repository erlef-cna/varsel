# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.CountLabel do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.count_label/1

  def variations do
    [
      %VariationGroup{
        id: :regular_noun,
        description: ~s(The common case — the plural just takes an "s".),
        variations: [
          %Variation{id: :none, attributes: %{count: 0, singular: "token"}},
          %Variation{id: :one, attributes: %{count: 1, singular: "token"}},
          %Variation{id: :many, attributes: %{count: 12, singular: "token"}}
        ]
      },
      %VariationGroup{
        id: :explicit_plural,
        description:
          "The search summaries read as a sentence, so the verb agrees with the count " <>
            "rather than the noun.",
        variations: [
          %Variation{
            id: :one_match,
            attributes: %{count: 1, singular: "match", plural: "matches"}
          },
          %Variation{
            id: :many_matches,
            attributes: %{count: 9, singular: "match", plural: "matches"}
          }
        ]
      },
      %VariationGroup{
        id: :unknown_count,
        description:
          "Ash leaves a page's total unset when it cannot cheaply count the result set. " <>
            "The count drops out rather than rendering as nil.",
        variations: [
          %Variation{id: :bare_plural, attributes: %{count: nil, singular: "CVE"}},
          %Variation{
            id: :bare_explicit_plural,
            attributes: %{count: nil, singular: "match", plural: "matches"}
          }
        ]
      }
    ]
  end
end
