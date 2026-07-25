# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.SummaryPanel do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.summary_panel/1

  def layout, do: :one_column

  def variations do
    [
      %Variation{
        id: :collapsed,
        description: "At rest: the headline facts, and a way in.",
        attributes: %{
          label: "Reserved pool",
          dot: "bg-base-content/30",
          count: 12,
          open?: false,
          toggle: "noop"
        },
        slots: [
          ~s|<:fact label="span" value="CVE-2026-0001 … CVE-2026-0012" mono?={true} />|,
          ~s|<:fact label="oldest" value="2026-06-01 · 54 d" />|,
          "<div>Hidden while collapsed.</div>"
        ]
      },
      %Variation{
        id: :open,
        description: "Expanded, revealing the records themselves.",
        attributes: %{
          label: "Reserved pool",
          dot: "bg-base-content/30",
          count: 2,
          open?: true,
          toggle: "noop"
        },
        slots: [
          ~s|<:fact label="span" value="CVE-2026-0001 … CVE-2026-0002" mono?={true} />|,
          """
          <div class="grid grid-cols-[10rem_1fr] items-center gap-3 py-1 text-sm">
            <span class="font-mono text-xs text-base-content/60">CVE-2026-0001</span>
            <span class="text-xs text-base-content/50 tabular-nums">reserved 2026-06-01</span>
          </div>
          """,
          """
          <div class="grid grid-cols-[10rem_1fr] items-center gap-3 py-1 text-sm">
            <span class="font-mono text-xs text-base-content/60">CVE-2026-0002</span>
            <span class="text-xs text-base-content/50 tabular-nums">reserved 2026-06-02</span>
          </div>
          """
        ]
      },
      %Variation{
        id: :warned,
        description: "`warn?` tints a fact that wants acting on — a reservation gone stale.",
        attributes: %{
          label: "Reserved pool",
          dot: "bg-base-content/30",
          count: 4,
          open?: false,
          toggle: "noop"
        },
        slots: [
          ~s|<:fact label="oldest" value="2026-01-04 · 202 d" warn?={true} />|,
          "<div></div>"
        ]
      },
      %Variation{
        id: :empty,
        description: "Nothing to show, so the disclosure refuses to open.",
        attributes: %{
          label: "Rejected",
          dot: "bg-error/60",
          count: 0,
          open?: false,
          toggle: "noop"
        },
        slots: ["<div></div>"]
      }
    ]
  end
end
