# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.ScopeTab do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.scope_tab/1

  def layout, do: :one_column

  # The component renders a tab's contents; the element around it — a link or
  # a button — belongs to the caller, and takes `scope_tab_class/1`.
  defp tab(active?) do
    class =
      if active?,
        do: "cursor-pointer pb-1 font-bold text-base-content shadow-[inset_0_-2px_0_var(--eef-blue)]",
        else: "cursor-pointer pb-1 text-base-content/60"

    """
    <div class="flex items-center gap-4 text-sm">
      <button class="#{class}"><.psb-variation/></button>
    </div>
    """
  end

  def variations do
    [
      %Variation{
        id: :active,
        description:
          "Active is ink, an accent count and an inset rule — \"you are here\" without " <>
            "leaning on weight alone.",
        attributes: %{active?: true, label: "All", count: 27},
        template: tab(true)
      },
      %Variation{
        id: :inactive,
        attributes: %{active?: false, label: "Draft", count: 4},
        template: tab(false)
      },
      %Variation{
        id: :no_count,
        description: "A scope that does not carry a count renders only its label.",
        attributes: %{active?: true, label: "Pipeline"},
        template: tab(true)
      },
      %Variation{
        id: :matched_elsewhere,
        description:
          "`matched?` tints the count — a search reaches every scope, so one you are " <>
            "not looking at says how many of its own the search found.",
        attributes: %{active?: false, label: "Pipeline", count: 3, matched?: true},
        template: tab(false)
      }
    ]
  end
end
