# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.ScopeTab do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.scope_tab/1

  def layout, do: :one_column

  # The tab styles itself; the element around it — a link where the scope
  # lives in the URL, a button where the view holds it — is the caller's.
  def template do
    """
    <div class="flex items-center gap-4 text-sm">
      <.psb-variation/>
    </div>
    """
  end

  def variations do
    [
      %VariationGroup{
        id: :states,
        description:
          "Active is ink, an accent count and an inset rule — \"you are here\" without " <>
            "leaning on weight alone.",
        variations: [
          %Variation{id: :active, attributes: %{active?: true, label: "All", count: 27}},
          %Variation{id: :inactive, attributes: %{active?: false, label: "Draft", count: 4}}
        ]
      },
      %Variation{
        id: :no_count,
        description: "A scope that does not carry a count renders only its label.",
        attributes: %{active?: true, label: "Pipeline"}
      },
      %Variation{
        id: :matched_elsewhere,
        description:
          "`matched?` tints the count — a search reaches every scope, so one you are " <>
            "not looking at says how many of its own the search found.",
        attributes: %{active?: false, label: "Pipeline", count: 3, matched?: true}
      }
    ]
  end
end
