# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.EmptyState do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.empty_state/1

  def layout, do: :one_column

  # It fills the width of the list card it stands in for.
  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %VariationGroup{
        id: :nothing_yet,
        description: "An empty collection — say what would put something here.",
        variations: [
          %Variation{id: :tokens, slots: ["No tokens yet — create one above."]},
          %Variation{
            id: :archive,
            slots: ["Nothing archived yet — cases land here when they are published or closed."]
          }
        ]
      },
      %VariationGroup{
        id: :no_matches,
        description: "A filter or search that matched nothing — a different sentence.",
        variations: [
          %Variation{id: :search, slots: ["No CVEs match your search."]},
          %Variation{id: :triage_filter, slots: ["No reports waiting for triage."]}
        ]
      },
      %Variation{
        id: :in_a_list_card,
        description: "Where it actually lands: in place of a list card's rows.",
        template: """
        <div class="rounded-box border border-base-300 bg-base-200 overflow-hidden">
          <div class="px-4 py-2.5 border-b border-base-300 text-sm text-base-content/70 tabular-nums">
            0 tokens
          </div>
          <.psb-variation/>
        </div>
        """,
        slots: ["No tokens yet — create one above."]
      }
    ]
  end
end
