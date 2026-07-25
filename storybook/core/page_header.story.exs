# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.PageHeader do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.page_header/1

  # Full-bleed band — the two-column layout would squash it.
  def layout, do: :one_column

  # The band spans the viewport in the app; the sandbox centers by default.
  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :default,
        attributes: %{eyebrow: "CNA Console"},
        slots: ["<:title>Cases</:title>"]
      },
      %Variation{
        id: :with_subtitle,
        attributes: %{eyebrow: "CNA Console"},
        slots: [
          "<:title>My queue</:title>",
          "<:subtitle>Everything assigned to you, newest first.</:subtitle>"
        ]
      },
      %Variation{
        id: :with_actions,
        attributes: %{eyebrow: "CNA Console"},
        slots: [
          "<:title>CASE-2026-0042</:title>",
          "<:subtitle>Draft · opened 3 days ago</:subtitle>",
          """
          <:actions>
            <button class="btn btn-eef-quiet btn-sm">Preview</button>
            <button class="btn btn-eef btn-sm">Submit for review</button>
          </:actions>
          """
        ]
      },
      %Variation{
        id: :public_page,
        description: "The public face — documentation, error and report pages pass their own eyebrow.",
        attributes: %{eyebrow: "Documentation"},
        slots: [
          "<:title>Scope</:title>",
          "<:subtitle>What the EEF CNA covers, and what it does not.</:subtitle>"
        ]
      },
      %Variation{
        id: :rich_slots,
        description: "Both `title` and `subtitle` take markup, not just text.",
        attributes: %{eyebrow: "Public record"},
        slots: [
          """
          <:title>
            <span class="font-mono">CVE-2026-1234</span>
            <span class="text-base-content/50 font-normal text-lg">· heap overflow in parser</span>
          </:title>
          """,
          """
          <:subtitle>
            Published 12 June 2026 · <a href="#" class="link">CVE record</a>
          </:subtitle>
          """
        ]
      }
    ]
  end
end
