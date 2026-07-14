# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ChartComponents do
  @moduledoc """
  HEEx function components that render the chart geometry produced by
  `VarselWeb.Charts`. No client JS — hover popovers are CSS-only (see
  the `.chart-*` / `.cwe-*` rules in `app.css`); the CWE donut/legend carry
  `phx-click` bindings handled by `CommonWeaknessesLive`.
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
  CWE distribution donut with clickable slices. `data` comes from
  `Charts.donut_geometry/1`. Slices `phx-click="slice"` (drill down or select);
  the LiveView decides based on `phx-value-drill`.
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
      <g
        :for={slice <- @data.slices}
        class="cwe-slice-group"
        role="button"
        tabindex="0"
        phx-click="slice"
        phx-value-cwe={slice.id}
        phx-value-drill={to_string(slice.has_children?)}
      >
        <path d={slice.arc} fill={slice.color} fill-rule={slice.full_ring? && "evenodd"} />
        <title>
          {slice.name}: {slice.count} CVEs ({slice.pct}%) — click to {drill_verb(slice)}
        </title>
      </g>

      <text
        :if={@data.total == 0}
        x={@data.center}
        y={@data.center}
        text-anchor="middle"
        fill={@data.axis_color}
      >
        No data
      </text>
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
        {@data.total}
      </text>
    </svg>
    """
  end

  @doc "CWE distribution legend. Rows `phx-click=\"select\"` to filter the CVE list."
  attr :data, :map, required: true

  def cwe_legend(assigns) do
    ~H"""
    <table class="cwe-legend-table">
      <tbody>
        <tr
          :for={slice <- @data.slices}
          class="cwe-legend-row"
          role="button"
          phx-click="select"
          phx-value-cwe={slice.id}
        >
          <td><span class="cwe-swatch" style={"background:#{slice.color}"}></span></td>
          <td>{slice.name} <span class="cwe-legend-id">{slice.id}</span></td>
          <td class="cwe-legend-count">{slice.count} ({slice.pct}%)</td>
        </tr>
      </tbody>
    </table>
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

  defp drill_verb(%{has_children?: true}), do: "drill down"
  defp drill_verb(_slice), do: "filter CVEs"

  defp clamp(value, min, max), do: value |> max(min) |> min(max)
end
