# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.SeverityChip do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.severity_chip/1

  def variations do
    [
      %VariationGroup{
        id: :compact,
        description: "The full CVSS scale, compact (initial + score).",
        variations: [
          %Variation{id: :critical, attributes: %{score: 9.8}},
          %Variation{id: :high, attributes: %{score: 8.1}},
          %Variation{id: :medium, attributes: %{score: 5.4}},
          %Variation{id: :low, attributes: %{score: 3.1}},
          %Variation{id: :none, attributes: %{score: 0.0}},
          %Variation{id: :no_score, attributes: %{score: nil}}
        ]
      },
      %VariationGroup{
        id: :full,
        description: "The same scale with the rating spelled out.",
        variations: [
          %Variation{id: :critical, attributes: %{score: 9.8, variant: :full}},
          %Variation{id: :high, attributes: %{score: 8.1, variant: :full}},
          %Variation{id: :medium, attributes: %{score: 5.4, variant: :full}},
          %Variation{id: :low, attributes: %{score: 3.1, variant: :full}},
          %Variation{id: :none, attributes: %{score: 0.0, variant: :full}}
        ]
      },
      %VariationGroup{
        id: :boundaries,
        description: "Bucket edges — 3.9/4.0, 6.9/7.0 and 8.9/9.0 must land either side.",
        variations: [
          %Variation{id: :low_max, attributes: %{score: 3.9, variant: :full}},
          %Variation{id: :medium_min, attributes: %{score: 4.0, variant: :full}},
          %Variation{id: :medium_max, attributes: %{score: 6.9, variant: :full}},
          %Variation{id: :high_min, attributes: %{score: 7.0, variant: :full}},
          %Variation{id: :high_max, attributes: %{score: 8.9, variant: :full}},
          %Variation{id: :critical_min, attributes: %{score: 9.0, variant: :full}}
        ]
      }
    ]
  end
end
