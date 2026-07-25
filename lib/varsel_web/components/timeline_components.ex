# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.TimelineComponents do
  @moduledoc """
  A version timeline: where a release line was vulnerable, and the versions
  that bound it.

  The caller works out what to plot; the timeline places it. Nodes carry a
  percentage along the track, spans tint the stretch between two of them, and
  a span reaching an edge runs off it — which is how "since the beginning" and
  "never fixed" are drawn.
  """
  use Phoenix.Component

  @doc """
  Renders one release line: its name, then the track with its nodes.

  `nodes` are maps of `:kind` (`:intro`, `:fix` or `:pending`), `:pos` — a
  percentage along the track — and `:tag`, the label hung off the node.
  `spans` are `%{start:, stop:}` percentage pairs marking where the line was
  vulnerable.

  The row reserves headroom for its own tags, which hang above the track and
  would otherwise collide with whatever sits above them. The positions and the
  gradient ride on `data-css-*` attributes rather than inline styles, which
  the strict CSP forbids; the CssVars hook copies them into the element's own
  style at mount and patch.
  """
  attr :id, :string, required: true
  attr :label, :string, required: true
  attr :nodes, :list, required: true
  attr :spans, :list, default: []

  def version_timeline(assigns) do
    ~H"""
    <div class="flex items-center gap-2.5 pt-6 pb-1">
      <span class="w-24 shrink-0 truncate text-right font-mono text-[0.68rem] text-base-content/50">
        {@label}
      </span>
      <div
        id={"tl-track-#{@id}"}
        phx-hook="CssVars"
        class="timeline-track flex-1"
        data-css---tl-gradient-stops={gradient_stops(@spans)}
      >
        <div
          :for={{node, index} <- Enum.with_index(@nodes)}
          id={"tl-node-#{@id}-#{index}"}
          phx-hook="CssVars"
          class={["timeline-node", node_class(node.kind), tag_anchor_class(node.pos)]}
          data-css---tl-pos={"#{node.pos}%"}
        >
          <span class="timeline-tag font-mono text-base-content/40" title={node.tag}>
            {node.tag}
          </span>
        </div>
      </div>
    </div>
    """
  end

  # The track is one gradient: base outside a span, warning within it, with
  # hard stops at both edges so a span reads as a band rather than a fade.
  defp gradient_stops([]), do: nil

  defp gradient_stops(spans) do
    spans
    |> Enum.sort_by(& &1.start)
    |> Enum.flat_map(fn %{start: start, stop: stop} ->
      [
        "var(--color-base-300) #{start}%",
        "var(--color-warning) #{start}%",
        "var(--color-warning) #{stop}%",
        "var(--color-base-300) #{stop}%"
      ]
    end)
    |> Enum.join(", ")
  end

  defp node_class(:intro), do: "is-intro"
  defp node_class(:fix), do: "is-fix"
  defp node_class(:pending), do: "is-pending"

  # A tag on a node near either end anchors inward, so it cannot spill out of
  # the card the track sits in.
  defp tag_anchor_class(pos) when pos <= 10, do: "tag-left"
  defp tag_anchor_class(pos) when pos >= 85, do: "tag-right"
  defp tag_anchor_class(_centered), do: nil
end
