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
        id: :title_only,
        description: "The least a header can say: where you are, and what this is.",
        slots: [
          "<:eyebrow>CNA Console</:eyebrow>",
          "<:title>Cases</:title>"
        ]
      },
      %Variation{
        id: :with_subtitle,
        description: "A `subtitle` says what the page is, in prose.",
        slots: [
          "<:eyebrow>CNA Console</:eyebrow>",
          "<:title>My queue</:title>",
          "<:subtitle>Everything assigned to you, newest first.</:subtitle>"
        ]
      },
      %Variation{
        id: :with_meta,
        description:
          "A `meta` slot carries what the page holds rather than what it is — " <>
            "the case board puts the scopes it can be seen through here.",
        slots: [
          "<:eyebrow>CNA Console</:eyebrow>",
          "<:title>Cases</:title>",
          """
          <:meta>
            <div class="flex items-center gap-4 text-sm">
              <VarselWeb.CoreComponents.scope_tab active?={true} label="Pipeline" count={16} />
              <VarselWeb.CoreComponents.scope_tab active?={false} label="Archive" count={33} />
            </div>
          </:meta>
          """
        ]
      },
      %Variation{
        id: :with_actions,
        description:
          "Actions sit beside the naming rows from `sm` up, settled against the foot " <>
            "of the band; narrower than that they stack underneath.",
        slots: [
          "<:eyebrow>CNA Console</:eyebrow>",
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
        id: :every_row,
        description: "All four naming rows, with the actions spanning them.",
        slots: [
          """
          <:eyebrow>
            Case <span class="font-mono">· CVE-2026-1234</span>
            <span class="text-base-content/50">· draft opened Jun 12, 2026</span>
          </:eyebrow>
          """,
          "<:title>Heap overflow in the packet parser</:title>",
          "<:subtitle>Awaiting review from a second POC.</:subtitle>",
          """
          <:meta>
            <div class="flex items-center gap-4 text-sm">
              <VarselWeb.CoreComponents.scope_tab active?={true} label="Draft" />
              <VarselWeb.CoreComponents.scope_tab active?={false} label="Review" />
              <VarselWeb.CoreComponents.scope_tab active?={false} label="Published" />
            </div>
          </:meta>
          """,
          """
          <:actions>
            <button class="btn btn-eef-quiet btn-sm">Preview</button>
            <button class="btn btn-eef btn-sm">Approve</button>
          </:actions>
          """
        ]
      },
      %Variation{
        id: :rich_slots,
        description: "Every slot takes markup, not just text.",
        slots: [
          "<:eyebrow>Public record</:eyebrow>",
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
          """,
          ~s(<:actions><button class="btn btn-eef-quiet btn-sm">JSON</button></:actions>)
        ]
      }
    ]
  end
end
