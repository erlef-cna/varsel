# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.PageContainer do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.page_container/1

  def layout, do: :one_column

  # It centers itself against the full viewport width in the app.
  def container, do: {:div, class: "w-full"}

  # Drawn on the container itself, so the padding variations show their own box
  # rather than a child's.
  @outline "border border-dashed border-base-300 rounded-box text-sm text-base-content/60"

  def variations do
    [
      %VariationGroup{
        id: :padding,
        description:
          "One measure and one set of gutters everywhere; `padding` sets the vertical rhythm. " <>
            "The dashed outline is the container itself.",
        variations: [
          %Variation{
            id: :normal,
            attributes: %{class: @outline},
            slots: ["Normal — the rhythm every list and detail page shares."]
          },
          %Variation{
            id: :tight,
            attributes: %{padding: :tight, class: @outline},
            slots: ["Tight — a notice bar riding above the page."]
          },
          %Variation{
            id: :hero,
            attributes: %{padding: :hero, class: @outline},
            slots: ["Hero — the landing band, given room to breathe."]
          }
        ]
      },
      %Variation{
        id: :right_rail,
        description:
          "A table of contents beside the content — the documentation and CVE pages. " <>
            "Rails only appear from `lg` up; below that they stack under the content.",
        slots: [
          """
          <:right>
            <div class="rounded-box border border-dashed border-base-300 p-3 text-center text-xs text-base-content/60">
              On this page
            </div>
          </:right>
          """,
          """
          <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
            Content. The column takes whatever the rail leaves.
          </div>
          """
        ]
      },
      %Variation{
        id: :left_rail,
        description: "A section nav on the left.",
        slots: [
          """
          <:left>
            <div class="rounded-box border border-dashed border-base-300 p-3 text-center text-xs text-base-content/60">
              Sections
            </div>
          </:left>
          """,
          """
          <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
            Content.
          </div>
          """
        ]
      },
      %Variation{
        id: :both_rails,
        description:
          "The case workspace: a narrow section nav, a wide rail of side panels, and the " <>
            "content between them.",
        slots: [
          """
          <:left width={:narrow}>
            <div class="rounded-box border border-dashed border-base-300 p-3 text-center text-xs text-base-content/60">
              Sections
            </div>
          </:left>
          """,
          """
          <:right width={:wide}>
            <div class="rounded-box border border-dashed border-base-300 p-3 text-center text-xs text-base-content/60">
              Suggestions, activity, people
            </div>
          </:right>
          """,
          """
          <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
            Content.
          </div>
          """
        ]
      },
      %VariationGroup{
        id: :rail_widths,
        description: "A rail is `:narrow`, `:normal` or `:wide` — the content takes the rest.",
        variations: [
          %Variation{
            id: :narrow,
            slots: [
              """
              <:right width={:narrow}>
                <div class="rounded-box border border-dashed border-base-300 p-3 text-center text-xs text-base-content/60">
                  narrow
                </div>
              </:right>
              """,
              """
              <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
                Content.
              </div>
              """
            ]
          },
          %Variation{
            id: :normal,
            slots: [
              """
              <:right width={:normal}>
                <div class="rounded-box border border-dashed border-base-300 p-3 text-center text-xs text-base-content/60">
                  normal
                </div>
              </:right>
              """,
              """
              <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
                Content.
              </div>
              """
            ]
          },
          %Variation{
            id: :wide,
            slots: [
              """
              <:right width={:wide}>
                <div class="rounded-box border border-dashed border-base-300 p-3 text-center text-xs text-base-content/60">
                  wide
                </div>
              </:right>
              """,
              """
              <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
                Content.
              </div>
              """
            ]
          }
        ]
      },
      %Variation{
        id: :with_spacing,
        description: "`class` carries the smaller deviations, like spacing a page's children.",
        attributes: %{class: "space-y-4"},
        slots: [
          """
          <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
            First card
          </div>
          """,
          """
          <div class="rounded-box border border-dashed border-base-300 p-6 text-center text-sm text-base-content/60">
            Second card, spaced by the container
          </div>
          """
        ]
      }
    ]
  end
end
