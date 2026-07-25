# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.ConsoleHeader do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.console_header/1

  # Full-bleed band — the two-column layout would squash it.
  def layout, do: :one_column

  # The band spans the viewport in the app; the sandbox centers by default.
  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :default,
        slots: ["<:title>Cases</:title>"]
      },
      %Variation{
        id: :with_subtitle,
        attributes: %{subtitle: "Everything assigned to you, newest first."},
        slots: ["<:title>My queue</:title>"]
      },
      %Variation{
        id: :with_actions,
        attributes: %{subtitle: "Draft · opened 3 days ago"},
        slots: [
          "<:title>CASE-2026-0042</:title>",
          """
          <:actions>
            <button class="btn btn-eef-quiet btn-sm">Preview</button>
            <button class="btn btn-eef btn-sm">Submit for review</button>
          </:actions>
          """
        ]
      },
      %Variation{
        id: :rich_title,
        description: "The title slot takes markup, not just text.",
        attributes: %{eyebrow: "Public record", subtitle: "Published 12 June 2026"},
        slots: [
          """
          <:title>
            <span class="font-mono">CVE-2026-1234</span>
            <span class="text-base-content/50 font-normal text-lg">· heap overflow in parser</span>
          </:title>
          """
        ]
      }
    ]
  end
end
