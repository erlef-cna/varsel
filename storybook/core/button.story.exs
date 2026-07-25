# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Button do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.button/1

  def variations do
    [
      %Variation{
        id: :default,
        description: "Soft primary — the default weight.",
        slots: ["Send!"]
      },
      %Variation{
        id: :primary,
        description: "The page's single strongest action.",
        attributes: %{variant: "primary"},
        slots: ["Publish"]
      },
      %Variation{
        id: :disabled,
        attributes: %{disabled: true},
        slots: ["Unavailable"]
      },
      %Variation{
        id: :link,
        description: "Any of href/navigate/patch renders an <a> instead of a <button>.",
        attributes: %{navigate: "/cases"},
        slots: ["Back to cases"]
      },
      %VariationGroup{
        id: :app_classes,
        description: "The console's own button classes, passed through `class`.",
        variations: [
          %Variation{id: :eef, attributes: %{class: "btn btn-eef btn-sm"}, slots: ["Brand blue"]},
          %Variation{
            id: :eef_quiet,
            attributes: %{class: "btn btn-eef-quiet btn-sm"},
            slots: ["Quiet outline"]
          },
          %Variation{
            id: :ghost_xs,
            attributes: %{class: "btn btn-ghost btn-xs"},
            slots: ["Row action"]
          }
        ]
      }
    ]
  end
end
