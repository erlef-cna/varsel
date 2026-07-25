# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.State do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.state/1

  def variations do
    [
      %VariationGroup{
        id: :case_lifecycle,
        description: "The case pipeline's lanes. Colour never carries the meaning alone.",
        variations: [
          %Variation{id: :draft, attributes: %{dot: "bg-base-content/30"}, slots: ["Draft"]},
          %Variation{id: :review, attributes: %{dot: "bg-info"}, slots: ["Review"]},
          %Variation{
            id: :approved,
            attributes: %{dot: "bg-[color:var(--violet)]"},
            slots: ["Approved"]
          },
          %Variation{id: :publishing, attributes: %{dot: "bg-info"}, slots: ["Publishing"]},
          %Variation{id: :published, attributes: %{dot: "bg-success"}, slots: ["Published"]},
          %Variation{id: :closed, attributes: %{dot: "bg-base-content/30"}, slots: ["Closed"]}
        ]
      },
      %VariationGroup{
        id: :cve_lifecycle,
        description: "CVE record states.",
        variations: [
          %Variation{id: :reserved, attributes: %{dot: "bg-warning"}, slots: ["Reserved"]},
          %Variation{
            id: :pending_update,
            attributes: %{dot: "bg-warning"},
            slots: ["Pending update"]
          },
          %Variation{id: :rejected, attributes: %{dot: "bg-error"}, slots: ["Rejected"]}
        ]
      },
      %Variation{
        id: :with_class,
        description: "`class` reaches the wrapper — here to shrink and mute the row.",
        attributes: %{dot: "bg-success", class: "text-xs text-base-content/60"},
        slots: ["Published"]
      }
    ]
  end
end
