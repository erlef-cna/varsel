# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Cve.UpstreamCveNotice do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CveView.upstream_cve_notice/1

  def layout, do: :one_column

  @body "The vulnerability is in code that packages in the Erlang ecosystem vendor from a " <>
          "project outside the EEF CNA's scope, so that project's CNA assigned the CVE. This " <>
          "page shows the EEF CNA's enrichment of CVE-2026-111497."

  def variations do
    [
      %Variation{
        id: :published,
        description: "The upstream CNA's title and summary, as text, with the link to cve.org.",
        attributes: %{
          cve_id: "CVE-2026-111497",
          title: "Heap buffer overflow in the brotli decoder",
          summary: "A crafted stream makes the brotli decoder write past the end of its output buffer."
        },
        slots: [@body]
      },
      %Variation{
        id: :reserved,
        description: "A RESERVED upstream CVE has no title or summary yet.",
        attributes: %{cve_id: "CVE-2026-111497"},
        slots: ["The ID is still RESERVED at MITRE. Publishing waits until its CNA publishes it."]
      },
      %Variation{
        id: :markup_in_title,
        description: "Another CNA's text renders as inert text, never as markup.",
        attributes: %{
          cve_id: "CVE-2026-111497",
          title: "<script>alert(1)</script> in <b>brotli</b>",
          summary: "Line one.\nLine two keeps its break."
        },
        slots: [@body]
      }
    ]
  end
end
