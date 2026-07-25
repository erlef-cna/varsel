# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Layout.EefLogo do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.Layouts.eef_logo/1

  def layout, do: :one_column

  def variations do
    [
      %Variation{
        id: :header,
        description: "The header wordmark, inlined so it inherits `currentColor`.",
        attributes: %{id: "logo-header", class: "h-7"}
      },
      %Variation{
        id: :footer,
        description: "The stacked footer variant.",
        attributes: %{id: "logo-footer", type: :footer, class: "h-20"}
      },
      %VariationGroup{
        id: :sizes,
        description: "The SVG fills the height set on its wrapper.",
        variations: [
          %Variation{id: :small, attributes: %{id: "logo-sm", class: "h-4"}},
          %Variation{id: :medium, attributes: %{id: "logo-md", class: "h-8"}},
          %Variation{id: :large, attributes: %{id: "logo-lg", class: "h-14"}}
        ]
      },
      %Variation{
        id: :on_navy,
        description: """
        In the navy bands the logo inherits white; elsewhere it takes the
        theme's ink colour. Wrapped in `.eef-band` here to show the band case.
        """,
        attributes: %{id: "logo-navy", class: "h-10 text-white"},
        template: """
        <div class="eef-band p-6 rounded-box">
          <.psb-variation/>
        </div>
        """
      }
    ]
  end
end
