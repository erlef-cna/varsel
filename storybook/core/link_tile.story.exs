# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.LinkTile do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.link_tile/1

  def variations do
    [
      %VariationGroup{
        id: :stacked,
        description: "The icon above the title, for a grid given room to breathe.",
        template: """
        <div class="grid sm:grid-cols-2 gap-4">
          <.psb-variation-group/>
        </div>
        """,
        variations: [
          %Variation{
            id: :scope,
            attributes: %{icon: "hero-viewfinder-circle", title: "CNA Scope", href: "#"},
            slots: ["What projects we cover"]
          },
          %Variation{
            id: :contact,
            attributes: %{icon: "hero-envelope", title: "Contact", href: "#"},
            slots: ["Report a vulnerability"]
          }
        ]
      },
      %VariationGroup{
        id: :inline,
        description: "The icon beside it, for a denser list of somewhere else to go.",
        template: """
        <div class="grid sm:grid-cols-2 gap-3">
          <.psb-variation-group/>
        </div>
        """,
        variations: [
          %Variation{
            id: :home,
            attributes: %{
              icon: "hero-home",
              title: "Home",
              href: "#",
              layout: :inline
            },
            slots: ["Overview and latest CVEs"]
          },
          %Variation{
            id: :cves,
            attributes: %{
              icon: "hero-list-bullet",
              title: "All CVEs",
              href: "#",
              layout: :inline
            },
            slots: ["Browse published records"]
          }
        ]
      }
    ]
  end
end
