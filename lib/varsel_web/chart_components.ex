# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ChartComponents do
  @moduledoc """
  HEEx function components that render the chart geometry produced by
  `VarselWeb.Charts`. No client JS — hover popovers are CSS-only (see
  the `.chart-*` / `.cwe-*` rules in `app.css`); the CWE donut/legend
  navigate via plain links rather than any LiveView event.
  """
  use VarselWeb, :html

  @doc """
  Quarterly CVE-activity area chart: the solid actual line, a dashed projection
  (hatched triangle to the current quarter's projected dot and an extrapolation
  to the next-quarter forecast), plotted dots with CSS hover popovers, and a
  legend. `data` comes from `Charts.cve_activity_data/1`.
  """
  attr :data, :map, required: true

  def cve_activity_chart(assigns) do
    ~H"""
    <svg
      viewBox={@data.view_box}
      role="img"
      aria-label="CVE publications by quarter"
      class="cve-activity-chart"
    >
      <defs>
        <linearGradient id="cveFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color={@data.color} stop-opacity="0.22" />
          <stop offset="100%" stop-color={@data.color} stop-opacity="0.02" />
        </linearGradient>
        <pattern
          id="cveHatch"
          patternUnits="userSpaceOnUse"
          width="6"
          height="6"
          patternTransform="rotate(45)"
        >
          <line
            x1="0"
            y1="0"
            x2="0"
            y2="6"
            stroke={@data.color}
            stroke-width="1"
            stroke-opacity="0.18"
          />
        </pattern>
      </defs>

      <%!-- grid + y labels --%>
      <g :for={tick <- @data.ticks}>
        <line
          x1={@data.left}
          y1={tick.y}
          x2={@data.right}
          y2={tick.y}
          stroke={@data.grid_color}
          stroke-width="1"
        />
        <text
          x={@data.left - 8}
          y={tick.y + 4}
          text-anchor="end"
          font-size="11"
          fill={@data.axis_color}
        >
          {tick.value}
        </text>
      </g>

      <%!-- projection fills (hatched) --%>
      <path
        :if={@data.projection && @data.projection.triangle}
        d={@data.projection.triangle.fill}
        fill="url(#cveHatch)"
      />
      <path
        :if={@data.projection && @data.projection.extrapolation}
        d={@data.projection.extrapolation.fill}
        fill="url(#cveHatch)"
      />

      <%!-- solid area + line --%>
      <path d={@data.solid.area} fill="url(#cveFill)" stroke="none" />
      <polyline
        points={@data.solid.line}
        fill="none"
        stroke={@data.color}
        stroke-width="2.5"
        stroke-linejoin="round"
        stroke-linecap="round"
      />

      <%!-- dashed projection edges --%>
      <polyline
        :if={@data.projection && @data.projection.triangle}
        points={@data.projection.triangle.dash}
        fill="none"
        stroke={@data.color}
        stroke-width="2"
        stroke-dasharray="5 4"
        stroke-linecap="round"
        opacity="0.6"
      />
      <polyline
        :if={@data.projection && @data.projection.extrapolation}
        points={@data.projection.extrapolation.dash}
        fill="none"
        stroke={@data.color}
        stroke-width="2"
        stroke-dasharray="5 4"
        stroke-linecap="round"
        opacity="0.6"
      />

      <%!-- x labels (two lines: quarter + year) --%>
      <g :for={pt <- @data.points} font-family="system-ui,sans-serif">
        <text
          x={pt.x}
          y={@data.label_y}
          text-anchor="middle"
          font-size="12"
          fill={label_fill(pt, @data)}
        >
          {quarter_part(pt.label)}
        </text>
        <text x={pt.x} y={@data.sublabel_y} text-anchor="middle" font-size="11" fill="#adb5bd">
          {year_part(pt.label)}
        </text>
      </g>

      <%!-- dots + popovers --%>
      <.activity_dots :for={pt <- @data.points} point={pt} data={@data} />

      <%!-- legend --%>
      <g font-family="system-ui,sans-serif">
        <% lx = @data.left + 130 %>
        <% ly = @data.legend_y %>
        <line
          x1={lx}
          y1={ly}
          x2={lx + 24}
          y2={ly}
          stroke={@data.color}
          stroke-width="2"
          stroke-linecap="round"
        />
        <circle cx={lx + 12} cy={ly} r="4" fill={@data.color} stroke={@data.color} stroke-width="2" />
        <text x={lx + 32} y={ly + 4} font-size="11" fill={@data.axis_color}>Actual CVEs</text>
        <line
          x1={lx + 150}
          y1={ly}
          x2={lx + 174}
          y2={ly}
          stroke={@data.color}
          stroke-width="2"
          stroke-dasharray="5 4"
          stroke-linecap="round"
          opacity="0.6"
        />
        <circle
          cx={lx + 162}
          cy={ly}
          r="4"
          fill="#fff"
          stroke={@data.color}
          stroke-width="2"
          stroke-dasharray="3 2"
        />
        <text x={lx + 182} y={ly + 4} font-size="11" fill={@data.axis_color}>
          Projected / Forecast
        </text>
      </g>
    </svg>
    """
  end

  # One quarter's dots: a solid actual dot; the current quarter adds a hollow
  # projected dot; the next quarter is a single hollow forecast dot.
  attr :point, :map, required: true
  attr :data, :map, required: true

  defp activity_dots(%{point: %{kind: :next}} = assigns) do
    ~H"""
    <.dot
      cx={@point.x}
      cy={@point.y}
      color={@data.color}
      hollow={true}
      tip={"#{@point.label} forecast: ~#{@point.count} CVEs"}
    />
    """
  end

  defp activity_dots(%{point: %{kind: :current}} = assigns) do
    ~H"""
    <.dot
      cx={@point.x}
      cy={@point.y}
      color={@data.color}
      hollow={false}
      tip={"#{@point.label}: #{@point.count} #{pluralize(@point.count)} (#{elapsed_pct(@point)}% of quarter elapsed)"}
    />
    <.dot
      cx={@data.projection.projected_x}
      cy={@data.projection.projected_y}
      color={@data.color}
      hollow={true}
      tip={"#{@point.label} projected: ~#{@point.projected} CVEs"}
    />
    """
  end

  defp activity_dots(assigns) do
    ~H"""
    <.dot
      cx={@point.x}
      cy={@point.y}
      color={@data.color}
      hollow={false}
      tip={"#{@point.label}: #{@point.count} #{pluralize(@point.count)}"}
    />
    """
  end

  # A dot with a CSS-only hover popover. `hollow` = dashed forecast/projection.
  attr :cx, :integer, required: true
  attr :cy, :integer, required: true
  attr :color, :string, required: true
  attr :hollow, :boolean, default: false
  attr :tip, :string, required: true

  defp dot(assigns) do
    box_w = round(String.length(assigns.tip) * 6.2 + 16)
    pop_x = assigns.cx |> Kernel.-(div(box_w, 2)) |> clamp(50, 670 - box_w)
    pop_y_above = assigns.cy - 14 - 24
    pop_y = if pop_y_above >= 20, do: pop_y_above, else: assigns.cy + 10

    assigns = assign(assigns, box_w: box_w, pop_x: pop_x, pop_y: pop_y)

    ~H"""
    <g class="chart-dot-group" tabindex="0">
      <circle
        cx={@cx}
        cy={@cy}
        r="5"
        class="chart-dot"
        fill={if @hollow, do: "#fff", else: @color}
        stroke={@color}
        stroke-width="2"
        stroke-dasharray={@hollow && "3 2"}
        opacity={@hollow && "0.85"}
      />
      <g class="chart-popover" aria-hidden="true">
        <rect x={@pop_x} y={@pop_y} width={@box_w} height="24" rx="4" fill="#fff" stroke="#dee2e6" />
        <text
          x={@pop_x + div(@box_w, 2)}
          y={@pop_y + 16}
          text-anchor="middle"
          font-size="11"
          fill="#212529"
          font-family="system-ui,sans-serif"
        >
          {@tip}
        </text>
      </g>
    </g>
    """
  end

  @doc """
  CWE distribution donut. `data` comes from `Charts.donut_geometry/1`; each
  slice's `:href` is where clicking it navigates, or `nil` for a slice with
  nowhere further to go (renders unlinked).

  A `:total` of 0 has no meaningful sweeps to divide up (`entries` may still
  be non-empty — every entry counting zero) — rather than per-entry
  degenerate zero-sweep arcs stacked on each other, it renders `:empty_ring`
  instead: one plain greyed full-circle stroke, so the empty state reads as
  intentional rather than broken.

  The center displays `:center_total`, not `:total` — they can differ (a
  view/subtree's own recursive count double-counts differently than the
  slice-sum does), while slice `:pct`/arcs always stay proportional to
  `:total`.
  """
  attr :data, :map, required: true

  def cwe_donut(assigns) do
    ~H"""
    <svg
      viewBox={"0 0 #{@data.size} #{@data.size}"}
      role="img"
      aria-label="CWE distribution"
      class="cwe-donut-svg"
    >
      <g :if={@data.total == 0}>
        <path d={@data.empty_ring} fill-rule="evenodd" class="cwe-donut-empty-ring" />
        <title>No CVEs to show</title>
      </g>
      <.donut_slice :for={slice <- @data.slices} :if={@data.total > 0} slice={slice} />

      <text
        x={@data.center}
        y={@data.center - 6}
        text-anchor="middle"
        font-size="14"
        fill={@data.axis_color}
        font-family="system-ui,sans-serif"
      >
        Total
      </text>
      <text
        x={@data.center}
        y={@data.center + 16}
        text-anchor="middle"
        font-size="26"
        font-weight="bold"
        fill="currentColor"
        font-family="system-ui,sans-serif"
      >
        {@data.center_total}
      </text>
    </svg>
    """
  end

  # SVG `<a>` behaves like HTML's for navigation purposes; a slice with no
  # `:href` (nothing to drill into further) renders its arc bare.
  attr :slice, :map, required: true

  defp donut_slice(%{slice: %{href: href}} = assigns) when is_binary(href) do
    ~H"""
    <.link navigate={@slice.href} class="cwe-slice-group">
      <path d={@slice.arc} fill={@slice.color} fill-rule={@slice.full_ring? && "evenodd"} />
      <title>{@slice.name}: {@slice.count} CVEs ({@slice.pct}%) — click to drill down</title>
    </.link>
    """
  end

  defp donut_slice(assigns) do
    ~H"""
    <g class="cwe-slice-group">
      <path d={@slice.arc} fill={@slice.color} fill-rule={@slice.full_ring? && "evenodd"} />
      <title>{@slice.name}: {@slice.count} CVEs ({@slice.pct}%)</title>
    </g>
    """
  end

  @doc """
  CWE distribution legend. Each row's `:href` is where clicking it
  navigates; a row with no `:href` renders unlinked.

  Built from CSS-table `<div>`/`<span>` markup rather than a real
  `<table>`/`<tr>`: an `<a>` is not a valid child of `<tbody>`, and an HTML
  parser foster-parents it (and its contents) OUT of the table at parse
  time, before any CSS runs — `display: table-row` on a hoisted element has
  no table ancestor left to lay out against, so a real `<table>` wrapper
  can never make a linked row render as a row. `role="table"` etc. keep it
  announced as a table to assistive tech despite the div/span markup.

  A non-zero `:unsliced_count` gets a trailing note row, rendered only when
  the caller passes an `unsliced_label` saying what the leftover means for
  that page — a bare count with no explanation is worse than none.
  """
  attr :data, :map, required: true
  attr :unsliced_label, :string, default: nil

  def cwe_legend(assigns) do
    ~H"""
    <div class="cwe-legend-table" role="table">
      <.legend_row :for={slice <- @data.slices} slice={slice} />
      <div
        :if={@unsliced_label && @data[:unsliced_count] not in [nil, 0]}
        class="cwe-legend-row cwe-legend-note"
        role="row"
      >
        <span class="cwe-legend-cell cwe-legend-cell-swatch" role="cell"></span>
        <span class="cwe-legend-cell cwe-legend-cell-name" role="cell">{@unsliced_label}</span>
        <span class="cwe-legend-cell cwe-legend-cell-count" role="cell">
          {@data.unsliced_count}
        </span>
        <span class="cwe-legend-cell cwe-legend-cell-pct" role="cell"></span>
      </div>
    </div>
    """
  end

  attr :slice, :map, required: true

  defp legend_row(%{slice: %{href: href}} = assigns) when is_binary(href) do
    ~H"""
    <.link navigate={@slice.href} class="cwe-legend-row" role="row">
      <.legend_cells slice={@slice} />
    </.link>
    """
  end

  defp legend_row(assigns) do
    ~H"""
    <div class="cwe-legend-row" role="row">
      <.legend_cells slice={@slice} />
    </div>
    """
  end

  attr :slice, :map, required: true

  defp legend_cells(assigns) do
    ~H"""
    <span class="cwe-legend-cell cwe-legend-cell-swatch" role="cell">
      <span
        class="cwe-swatch"
        phx-hook="CssVars"
        id={"cwe-swatch-#{@slice.id}"}
        data-css-background={@slice.color}
      ></span>
    </span>
    <span class="cwe-legend-cell cwe-legend-cell-name" role="cell">
      {@slice.name} <span class="cwe-legend-id">{@slice.id}</span>
    </span>
    <span class="cwe-legend-cell cwe-legend-cell-count" role="cell">{@slice.count}</span>
    <span class="cwe-legend-cell cwe-legend-cell-pct" role="cell">({@slice.pct}%)</span>
    """
  end

  ## helpers

  defp quarter_part(label), do: label |> String.split(" ") |> List.first()
  defp year_part(label), do: label |> String.split(" ") |> List.last()

  defp label_fill(%{kind: :next}, _data), do: "#adb5bd"
  defp label_fill(_pt, data), do: data.axis_color

  defp elapsed_pct(%{elapsed: elapsed}), do: round(elapsed * 100)
  defp elapsed_pct(_pt), do: 0

  defp pluralize(1), do: "CVE"
  defp pluralize(_), do: "CVEs"

  defp clamp(value, min, max), do: value |> max(min) |> min(max)
end
