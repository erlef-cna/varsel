# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.DerivationStatus do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AffectedComponents.derivation_status/1

  def layout, do: :one_column

  def description, do: "What the derived ranges are currently worth."

  defp ago(hours), do: DateTime.shift(DateTime.utc_now(), hour: -hours)

  def variations do
    [
      %Variation{
        id: :current,
        description: "Derived after every change we know about. It recedes — there is nothing to act on.",
        attributes: %{state: :current, at: ago(0), can_refresh: true}
      },
      %Variation{
        id: :ageing,
        description:
          "Still current, but old enough that releases may have been cut since. Nothing in " <>
            "the case is wrong, so this dims rather than warns.",
        attributes: %{state: :ageing, at: ago(72), can_refresh: true}
      },
      %Variation{
        id: :outdated,
        description:
          "The facts changed after the last run, so the ranges on screen are wrong. The only " <>
            "state that warns, and the one that blocks publishing.",
        attributes: %{state: :outdated, at: ago(2), can_refresh: true}
      },
      %Variation{
        id: :never,
        description:
          ~s(Nothing has run. The empty ranges below mean "unknown", not "none" — worth ) <>
            "saying plainly, but not an error.",
        attributes: %{state: :never, can_refresh: true}
      },
      %Variation{
        id: :refreshing,
        description: "While it runs, the button says so and stops taking clicks.",
        attributes: %{state: :outdated, at: ago(2), can_refresh: true, refreshing: true}
      },
      %Variation{
        id: :read_only,
        description:
          "Without the right to derive, the state still reports — a reader needs to know " <>
            "whether to believe the ranges as much as an author does.",
        attributes: %{state: :outdated, at: ago(2), can_refresh: false}
      }
    ]
  end
end
