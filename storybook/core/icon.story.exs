# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Icon do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.icon/1

  def variations do
    [
      %VariationGroup{
        id: :styles,
        description: """
        Heroicons come in outline (default), `-solid`, `-mini` and `-micro`.
        The glyphs are extracted from `deps/heroicons` by the Tailwind plugin
        in `assets/vendor/heroicons.js`.
        """,
        variations: [
          %Variation{id: :outline, attributes: %{name: "hero-shield-check", class: "size-6"}},
          %Variation{id: :solid, attributes: %{name: "hero-shield-check-solid", class: "size-6"}},
          %Variation{id: :mini, attributes: %{name: "hero-shield-check-mini", class: "size-5"}},
          %Variation{id: :micro, attributes: %{name: "hero-shield-check-micro", class: "size-4"}}
        ]
      },
      %VariationGroup{
        id: :in_use,
        description: "Icons the console actually uses.",
        variations: [
          %Variation{
            id: :search,
            attributes: %{name: "hero-magnifying-glass-mini", class: "size-5"}
          },
          %Variation{id: :info, attributes: %{name: "hero-information-circle", class: "size-5"}},
          %Variation{id: :error, attributes: %{name: "hero-exclamation-circle", class: "size-5"}},
          %Variation{id: :close, attributes: %{name: "hero-x-mark", class: "size-5"}},
          %Variation{id: :user, attributes: %{name: "hero-user-circle", class: "size-5"}},
          %Variation{id: :menu, attributes: %{name: "hero-bars-3", class: "size-5"}}
        ]
      },
      %Variation{
        id: :colored,
        description: "Icons inherit `currentColor`, so text utilities tint them.",
        attributes: %{name: "hero-exclamation-triangle", class: "size-8 text-warning"}
      },
      %Variation{
        id: :animated,
        description: "The reconnect spinner, as used by the flash group.",
        attributes: %{name: "hero-arrow-path", class: "size-6 motion-safe:animate-spin"}
      }
    ]
  end
end
