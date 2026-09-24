# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.ConsoleMenu do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.console_menu/1

  def layout, do: :one_column

  def description, do: "A console control that picks one option, beside the search box."

  # The menu itself only opens on focus, so a variation shows the trigger —
  # which is the part that has to read correctly at a glance, since it carries
  # the current choice.
  def container, do: {:div, class: "flex justify-end w-full"}

  defp sort_options do
    [
      {:newest, "Newest first"},
      {:oldest, "Oldest first"},
      {:severity, "Severity"},
      {:title, "Title"}
    ]
  end

  def variations do
    [
      %Variation{
        id: :default_choice,
        description: "The trigger names the current choice, so the order is readable unopened.",
        attributes: %{
          id: "sort-default",
          label: "Sort",
          value: :newest,
          options: sort_options(),
          event: "sort"
        }
      },
      %Variation{
        id: :another_choice,
        description: "Any option can be the current one; the trigger follows it.",
        attributes: %{
          id: "sort-severity",
          label: "Severity choice",
          value: :severity,
          options: sort_options(),
          event: "sort"
        }
      },
      %Variation{
        id: :two_options,
        description: "A control with only two options reads the same way.",
        attributes: %{
          id: "sort-pair",
          label: "Show",
          value: :mine,
          options: [{:mine, "Mine"}, {:everyone, "Everyone"}],
          event: "sort"
        }
      }
    ]
  end
end
