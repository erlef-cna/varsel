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
      },
      %Variation{
        id: :filter,
        description:
          "A filter names its own icon, and its options can be any value, such as a " <>
            "record's id. A long choice is cut off in the trigger.",
        attributes: %{
          id: "assignee-filter",
          label: "Assignee",
          icon: "hero-user-mini",
          value: "3f2a",
          options: [
            {"all", "Everyone"},
            {"me", "Me"},
            {"3f2a", "Someone with a rather long display name"}
          ],
          event: "assignee"
        }
      },
      %Variation{
        id: :searchable,
        description:
          "A long list gets a search box above its options, which narrows them as " <>
            "you type. Enter picks the first one left.",
        attributes: %{
          id: "assignee-search",
          label: "Assignee",
          icon: "hero-user-mini",
          value: "all",
          options: [{"all", "Everyone"} | Enum.map(1..40, &{"user-#{&1}", "Person #{&1}"})],
          event: "assignee",
          searchable: true
        }
      },
      %Variation{
        id: :groups,
        description:
          "A control that chooses more than one thing: each group is a titled set " <>
            "with its own current choice, and the trigger names them all.",
        attributes: %{
          id: "sort-groups",
          label: "Sort",
          groups: [
            %{
              label: "Packages",
              event: "sort_packages",
              value: :recent,
              options: [{:recent, "Latest update"}, {:name, "Name"}]
            },
            %{label: "Cases", event: "sort", value: :newest, options: sort_options()}
          ]
        }
      }
    ]
  end
end
