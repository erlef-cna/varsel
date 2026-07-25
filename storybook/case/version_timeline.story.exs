# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.VersionTimeline do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.TimelineComponents.version_timeline/1

  def layout, do: :one_column

  # The track fills the card it sits in, and the tags need room above it.
  def container, do: {:div, class: "w-full px-6 py-4"}

  def variations do
    [
      %Variation{
        id: :one_range,
        description: "A version introduced it, a later one fixed it.",
        attributes: %{
          id: "one-range",
          label: "hex",
          nodes: [
            %{kind: :intro, pos: 6, tag: "1.2.0"},
            %{kind: :fix, pos: 94, tag: "1.2.4"}
          ],
          spans: [%{start: 6, stop: 94}]
        }
      },
      %Variation{
        id: :since_the_beginning,
        description:
          "Vulnerable from the first release: the span runs off the left edge and there " <>
            "is no node to start it.",
        attributes: %{
          id: "open-start",
          label: "hex",
          nodes: [%{kind: :fix, pos: 94, tag: "0.6.0"}],
          spans: [%{start: 0, stop: 94}]
        }
      },
      %Variation{
        id: :never_fixed,
        description: "No fix on this line yet, so the span runs off the right edge.",
        attributes: %{
          id: "open-end",
          label: "github",
          nodes: [%{kind: :intro, pos: 6, tag: "17.4"}],
          spans: [%{start: 6, stop: 100}]
        }
      },
      %Variation{
        id: :several_ranges,
        description:
          "Two release lines on one track: fixed, reintroduced, fixed again. The " <>
            "stretches between are untinted.",
        attributes: %{
          id: "multi",
          label: "otp",
          nodes: [
            %{kind: :intro, pos: 6, tag: "25.0"},
            %{kind: :fix, pos: 35, tag: "25.3.2"},
            %{kind: :intro, pos: 64, tag: "26.1"},
            %{kind: :fix, pos: 94, tag: "26.2.5"}
          ],
          spans: [%{start: 6, stop: 35}, %{start: 64, stop: 94}]
        }
      },
      %Variation{
        id: :pending_fix,
        description: "A fix is declared but unreleased — a hollow node at the very end.",
        attributes: %{
          id: "pending",
          label: "hex",
          nodes: [
            %{kind: :intro, pos: 6, tag: "2.0.0"},
            %{kind: :pending, pos: 94, tag: "fix unreleased"}
          ],
          spans: [%{start: 6, stop: 100}]
        }
      },
      %Variation{
        id: :crowded,
        description: "Tags near either end anchor inward so they cannot spill out of the card.",
        attributes: %{
          id: "crowded",
          label: "git",
          nodes: [
            %{kind: :intro, pos: 6, tag: "be95772"},
            %{kind: :fix, pos: 50, tag: "2691a80"},
            %{kind: :intro, pos: 72, tag: "521bcfa"},
            %{kind: :fix, pos: 94, tag: "9f3e1c2"}
          ],
          spans: [%{start: 6, stop: 50}, %{start: 72, stop: 94}]
        }
      }
    ]
  end
end
