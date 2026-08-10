# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Disclosure do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.DisclosureComponents.disclosure/1

  def layout, do: :one_column

  def description, do: "A section that folds its rows away, never its verbs."

  def variations do
    [
      %Variation{
        id: :closed,
        description:
          "Collapsed, and still saying how much it holds and what you may do — the count " <>
            "and the button are the reason this is a view rather than a mode.",
        attributes: %{id: "story-disclosure-closed", title: "Boundary facts", count: 2},
        slots: [
          ~s(<:actions><span class="link link-hover text-primary">Add boundary</span></:actions>),
          ~s(<p class="text-xs text-base-content/60">Two facts live here.</p>)
        ]
      },
      %Variation{
        id: :open,
        description: "Opened. The header is identical; only rows appeared beneath it.",
        attributes: %{
          id: "story-disclosure-open",
          title: "Boundary facts",
          count: 2,
          open?: true
        },
        slots: [
          ~s(<:actions><span class="link link-hover text-primary">Add boundary</span></:actions>),
          ~s(<p class="text-xs text-base-content/60">Two facts live here.</p>)
        ]
      },
      %Variation{
        id: :empty,
        description: "Nothing inside yet: the section says so and still offers the way to fill it.",
        attributes: %{
          id: "story-disclosure-empty",
          title: "Program files",
          count: 0,
          open?: true
        },
        slots: [
          ~s(<:actions><span class="link link-hover text-primary">Add file</span></:actions>),
          ~s(<:empty>No program files recorded.</:empty>)
        ]
      },
      %Variation{
        id: :countless,
        description: "A section whose contents do not count into a number.",
        attributes: %{id: "story-disclosure-countless", title: "Raw record", open?: false},
        slots: [~s(<p class="text-xs text-base-content/60">Some detail.</p>)]
      }
    ]
  end
end
