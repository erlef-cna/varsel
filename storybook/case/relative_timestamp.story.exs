# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.RelativeTimestamp do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.relative_timestamp/1

  defp ago(seconds), do: DateTime.add(DateTime.utc_now(), -seconds, :second)

  def variations do
    [
      %VariationGroup{
        id: :scale,
        description: """
        Under a minute reads "just now", then minutes, hours and days; past
        seven days it falls back to an absolute date. The full UTC datetime is
        always in the `title` attribute — hover any of these.
        """,
        variations: [
          %Variation{id: :just_now, attributes: %{at: ago(20)}},
          %Variation{id: :minutes, attributes: %{at: ago(5 * 60)}},
          %Variation{id: :hours, attributes: %{at: ago(3 * 3600)}},
          %Variation{id: :days, attributes: %{at: ago(3 * 86_400)}},
          %Variation{id: :absolute, attributes: %{at: ago(30 * 86_400)}}
        ]
      },
      %Variation{
        id: :styled,
        description: "`class` styles the wrapper — the feed's muted treatment.",
        attributes: %{at: ago(7200), class: "text-xs text-base-content/50"}
      }
    ]
  end
end
