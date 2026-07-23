# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Charts do
  @moduledoc """
  Data layer for the CVE-activity and CWE-distribution charts (the Phoenix port
  of the Jekyll `cve_chart_generator.rb` / `cwe_chart_generator.rb`).

  These functions compute aggregations and SVG *geometry* only — pixel
  coordinates, arc/area paths, projection points — and return plain maps.
  `VarselWeb.ChartComponents` renders that data as HEEx `~H` markup.
  Keeping the two apart makes the aggregation unit-testable with a fixed `now`
  and keeps the markup out of string interpolation.
  """
  alias Varsel.CVE
  alias Varsel.CWE

  @color "#1b85cb"
  @axis_color "#6c757d"
  @grid_color "#e9ecef"

  ## ================================================================ CVE activity

  # geometry
  @view_w 700
  @view_h 280
  @left 50
  @top 20
  @width 620
  @height 180
  @bottom @top + @height

  @doc """
  Data for the quarterly CVE-activity chart: viewBox geometry, grid ticks, the
  solid area/line path, the dashed projection (triangle to the current
  quarter's projected dot + extrapolation to the next-quarter forecast), and
  every plotted point with its pixel position. `now` defaults to the current
  UTC time; pass one for deterministic rendering/tests. Consumed by
  `VarselWeb.ChartComponents.cve_activity_chart/1`.
  """
  @spec cve_activity_data(DateTime.t()) :: map()
  def cve_activity_data(now \\ DateTime.utc_now()) do
    cve_activity_data_from(published_dates(), now)
  end

  @doc "Builds activity-chart data from a precomputed list of published DateTimes."
  @spec cve_activity_data_from([DateTime.t()], DateTime.t()) :: map()
  def cve_activity_data_from(dates, now) do
    %{points: points, y_max: y_max} = build_points(dates, now)
    n = length(points)

    plotted =
      points
      |> Enum.with_index()
      |> Enum.map(fn {pt, i} ->
        Map.merge(pt, %{x: x_for(i, n), y: y_for(pt.count, y_max)})
      end)

    cur = Enum.find(plotted, &(&1.kind == :current))
    nxt = Enum.find(plotted, &(&1.kind == :next))

    %{
      view_box: "0 0 #{@view_w} #{@view_h}",
      color: @color,
      axis_color: @axis_color,
      grid_color: @grid_color,
      left: @left,
      right: @left + @width,
      top: @top,
      bottom: @bottom,
      label_y: @bottom + 20,
      sublabel_y: @bottom + 34,
      legend_y: @bottom + 52,
      ticks: ticks(y_max),
      points: plotted,
      solid: solid_path(plotted),
      projection: projection(plotted, cur, nxt, y_max)
    }
  end

  defp published_dates do
    [load: [:date_published], actor: nil]
    |> CVE.list_published_cve_records!()
    |> Enum.map(& &1.date_published)
    |> Enum.reject(&is_nil/1)
  end

  # ---- aggregation

  @doc false
  def build_points(dates, now) do
    counts = aggregate_quarters(dates)
    {cur_year, cur_q} = quarter_of(now)
    cur_key = {cur_year, cur_q}
    counts = Map.put_new(counts, cur_key, 0)

    sorted_keys = counts |> Map.keys() |> Enum.sort()
    raw_count = counts[cur_key]

    daily_rate = count_last_60_days(dates, now) / 60.0
    days_remaining = max(days_remaining_in_quarter(now), 0)
    projected = round(raw_count + daily_rate * days_remaining)
    next_count = round(daily_rate * 91)
    elapsed = quarter_elapsed_fraction(now)

    y_max =
      counts |> Map.values() |> Kernel.++([projected, next_count]) |> Enum.max() |> nice_y_max()

    # leading zero-quarter
    {first_year, first_q} = List.first(sorted_keys)
    {prev_year, prev_q} = prev_quarter(first_year, first_q)

    lead = [%{kind: :confirmed, label: "Q#{prev_q} #{prev_year}", count: 0}]

    body =
      Enum.map(sorted_keys, fn {year, q} = key ->
        label = "Q#{q} #{year}"

        if key == cur_key do
          %{
            kind: :current,
            label: label,
            count: raw_count,
            projected: projected,
            elapsed: elapsed
          }
        else
          %{kind: :confirmed, label: label, count: counts[key]}
        end
      end)

    tail =
      if Enum.any?(sorted_keys, &(&1 != cur_key)) do
        {ny, nq} = next_quarter(cur_year, cur_q)
        [%{kind: :next, label: "Q#{nq} #{ny}", count: next_count}]
      else
        []
      end

    %{points: lead ++ body ++ tail, y_max: y_max}
  end

  defp aggregate_quarters(dates) do
    Enum.reduce(dates, %{}, fn dt, acc ->
      Map.update(acc, quarter_of(dt), 1, &(&1 + 1))
    end)
  end

  defp quarter_of(%DateTime{year: year, month: month}), do: {year, div(month - 1, 3) + 1}

  defp prev_quarter(year, 1), do: {year - 1, 4}
  defp prev_quarter(year, q), do: {year, q - 1}

  defp next_quarter(year, 4), do: {year + 1, 1}
  defp next_quarter(year, q), do: {year, q + 1}

  defp count_last_60_days(dates, now) do
    cutoff = DateTime.add(now, -60 * 86_400, :second)
    Enum.count(dates, &(DateTime.compare(&1, cutoff) != :lt and DateTime.before?(&1, now)))
  end

  defp days_remaining_in_quarter(now) do
    {year, q} = quarter_of(now)
    {ny, nq} = next_quarter(year, q)
    q_end = DateTime.new!(Date.new!(ny, (nq - 1) * 3 + 1, 1), ~T[00:00:00])
    DateTime.diff(q_end, now, :second) / 86_400
  end

  # Fraction (0..1) of the current quarter that has elapsed at `now`.
  defp quarter_elapsed_fraction(now) do
    {year, q} = quarter_of(now)
    q_start = DateTime.new!(Date.new!(year, (q - 1) * 3 + 1, 1), ~T[00:00:00])
    {ny, nq} = next_quarter(year, q)
    q_end = DateTime.new!(Date.new!(ny, (nq - 1) * 3 + 1, 1), ~T[00:00:00])

    total = DateTime.diff(q_end, q_start, :second)
    elapsed = DateTime.diff(now, q_start, :second)
    (elapsed / total) |> min(1.0) |> max(0.0)
  end

  # smallest 1-2-5 nice max giving 3–6 ticks
  defp nice_y_max(raw_max) do
    raw_max = max(raw_max, 1)
    magnitude = max(Integer.pow(10, max(floor(:math.log10(raw_max)) - 1, 0)), 1)
    steps = Enum.map([1, 2, 5, 10, 20, 25, 50, 100], &(&1 * magnitude))

    Enum.find_value(steps, raw_max, fn step ->
      snapped = ceil(raw_max / step) * step
      ticks = div(snapped, step)
      if ticks >= 3 and ticks <= 6, do: snapped
    end)
  end

  # ---- geometry (pure data; markup lives in ChartComponents)

  # Solid line/area covers everything except the next-quarter forecast point.
  defp solid_path(plotted) do
    solid = Enum.reject(plotted, &(&1.kind == :next))
    coords = Enum.map(solid, &{&1.x, &1.y})

    line = Enum.map_join(coords, " ", fn {x, y} -> "#{x},#{y}" end)

    area =
      case coords do
        [] ->
          ""

        _ ->
          {x_start, _} = List.first(coords)
          {x_end, _} = List.last(coords)
          seg = Enum.map_join(coords, " L ", fn {x, y} -> "#{x},#{y}" end)
          "M #{x_start},#{@bottom} L #{seg} L #{x_end},#{@bottom} Z"
      end

    %{line: line, area: area}
  end

  # Dashed projection: a hatched triangle from the previous quarter's real dot
  # up to the current quarter's projected dot, plus a hatched extrapolation to
  # the next-quarter forecast dot. Returns nil when there is no current point.
  defp projection(_plotted, nil, _nxt, _y_max), do: nil

  defp projection(plotted, cur, nxt, y_max) do
    proj_y = y_for(cur.projected, y_max)
    cur_idx = Enum.find_index(plotted, &(&1.kind == :current))
    prev = if cur_idx && cur_idx > 0, do: Enum.at(plotted, cur_idx - 1)

    triangle =
      if prev do
        %{
          fill: "M #{prev.x},#{prev.y} L #{cur.x},#{proj_y} L #{cur.x},#{cur.y} Z",
          dash: "#{prev.x},#{prev.y} #{cur.x},#{proj_y}"
        }
      end

    extrapolation =
      if nxt do
        %{
          fill: "M #{cur.x},#{@bottom} L #{cur.x},#{proj_y} L #{nxt.x},#{nxt.y} L #{nxt.x},#{@bottom} Z",
          dash: "#{cur.x},#{proj_y} #{nxt.x},#{nxt.y}"
        }
      end

    %{projected_x: cur.x, projected_y: proj_y, triangle: triangle, extrapolation: extrapolation}
  end

  defp ticks(y_max) do
    step = max(div(y_max, 4), 1)
    for value <- 0..y_max//step, do: %{value: value, y: y_for(value, y_max)}
  end

  defp x_for(_i, 1), do: @left + div(@width, 2)
  defp x_for(i, total), do: @left + round(i * @width / (total - 1))

  defp y_for(count, y_max), do: @bottom - round(count * @height / y_max)

  ## ================================================================ CWE donut

  @donut_r_outer 160
  @donut_r_inner 90
  @donut_size 340
  @donut_colors ~w(#1b85cb #0d6efd #17a2b8 #198754 #20c997 #ffc107 #fd7e14 #dc3545 #e83e8c #6f42c1 #6610f2 #6c757d)

  @doc """
  CWE distribution at a `focus` node, as `%{entries, focus, breadcrumb}`.

  Each published CVE's CWE ids carry an ancestor chain (walking `child_of` to
  the top of the tree). At the top level (`focus == nil`) each CVE-CWE is
  grouped by the root of its chain; drilling into a node groups by the child
  of that node on the chain. Every bucket is therefore CVE-backed. Entries
  carry the set of contributing CVE ids so the caller can show a filtered
  list, and `has_children?` marks entries that can be drilled into further.
  """
  @spec cwe_distribution(String.t() | nil) :: %{
          entries: [map()],
          focus: map() | nil,
          breadcrumb: [map()]
        }
  def cwe_distribution(focus \\ nil) do
    catalog = cwe_catalog()
    focus_id = parse_cwe_id(focus)
    refs = cwe_cve_refs(catalog)

    entries =
      refs
      |> Enum.flat_map(fn %{chain: chain, cve_id: cve_id} ->
        case bucket_for(chain, focus_id) do
          nil -> []
          node -> [{node, cve_id}]
        end
      end)
      |> Enum.group_by(fn {node, _cve} -> node end, fn {_node, cve} -> cve end)
      |> Enum.map(fn {node, cves} ->
        cve_ids = Enum.uniq(cves)

        %{
          id: "CWE-#{node}",
          name: cwe_name(catalog, node),
          count: length(cve_ids),
          cve_ids: cve_ids,
          has_children?: any_child_below?(refs, focus_id, node)
        }
      end)
      |> Enum.sort_by(& &1.count, :desc)

    %{
      entries: entries,
      focus: focus_entry(catalog, focus_id),
      breadcrumb: breadcrumb(catalog, focus_id)
    }
  end

  @doc """
  Enriches a distribution result with the geometry the donut component needs:
  a `:total`, each entry gets `:color`, `:pct` and (for the donut) an `:arc`
  path, and a `:full_ring?` flag for the single-100%-slice case. Consumed by
  `VarselWeb.ChartComponents.cwe_donut/1` + `cwe_legend/1`.
  """
  @spec donut_geometry(map()) :: map()
  def donut_geometry(%{entries: entries} = dist) do
    total = entries |> Enum.map(& &1.count) |> Enum.sum()
    center = div(@donut_size, 2)

    {slices, _angle} =
      entries
      |> Enum.with_index()
      |> Enum.map_reduce(-90.0, fn {entry, idx}, start_angle ->
        sweep = if total > 0, do: entry.count / total * 360, else: 0.0
        end_angle = start_angle + sweep
        full_ring? = sweep >= 359.999

        slice =
          Map.merge(entry, %{
            color: Enum.at(@donut_colors, rem(idx, length(@donut_colors))),
            pct: percentage(entry.count, total),
            full_ring?: full_ring?,
            arc:
              if(full_ring?,
                do: full_ring_path(center),
                else: arc_path(center, start_angle, end_angle)
              )
          })

        {slice, end_angle}
      end)

    Map.merge(dist, %{
      total: total,
      center: center,
      size: @donut_size,
      colors: @donut_colors,
      slices: slices,
      color: @color,
      axis_color: @axis_color
    })
  end

  defp percentage(_count, 0), do: 0.0
  defp percentage(count, total), do: Float.round(count / total * 100, 1)

  # For a CWE ancestor chain (leaf-first list of ids) and a focus id, the id
  # of the bucket this chain contributes to: the chain element that is a direct
  # child of focus (or the chain root when focus is nil). nil if the chain does
  # not pass through focus.
  defp bucket_for(chain, nil), do: List.last(chain)

  defp bucket_for(chain, focus_id) do
    case Enum.find_index(chain, &(&1 == focus_id)) do
      nil -> nil
      0 -> nil
      idx -> Enum.at(chain, idx - 1)
    end
  end

  # Whether drilling into `node` (under `focus`) would yield further buckets —
  # i.e. some CVE chain has a descendant of `node` strictly below it.
  defp any_child_below?(refs, _focus_id, node) do
    Enum.any?(refs, fn %{chain: chain} ->
      case Enum.find_index(chain, &(&1 == node)) do
        nil -> false
        0 -> false
        _idx -> true
      end
    end)
  end

  # Per published-CVE CWE reference with its ancestor chain (leaf-first).
  defp cwe_cve_refs(catalog) do
    [actor: nil]
    |> CVE.list_published_cve_records!()
    |> Enum.flat_map(fn record ->
      cve_id = record.cve_json["cveMetadata"]["cveId"]

      record.cve_json
      |> get_in(["containers", "cna", "problemTypes"])
      |> List.wrap()
      |> Enum.flat_map(&Map.get(&1, "descriptions", []))
      |> Enum.map(& &1["cweId"])
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&parse_cwe_id/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> Enum.map(fn id -> %{cve_id: cve_id, cwe_id: id, chain: ancestor_chain(catalog, id)} end)
    end)
  end

  # CWE catalog as %{id => weakness} with child_of edges loaded.
  defp cwe_catalog do
    [load: [:related_weakness_relationships]]
    |> CWE.list_weaknesses!()
    |> Map.new(fn w -> {w.cwe_id, w} end)
  rescue
    _error -> %{}
  end

  # Ancestor chain for a CWE id, leaf-first (self, parent, …, root).
  defp ancestor_chain(catalog, id), do: ancestor_chain(catalog, id, [])

  defp ancestor_chain(catalog, id, acc) do
    cond do
      id in acc ->
        Enum.reverse(acc)

      is_nil(catalog[id]) ->
        Enum.reverse([id | acc])

      true ->
        case parent_cwe_id(catalog[id]) do
          nil -> Enum.reverse([id | acc])
          parent -> ancestor_chain(catalog, parent, [id | acc])
        end
    end
  end

  defp parent_cwe_id(weakness) do
    weakness.related_weakness_relationships
    |> Enum.find(&(&1.nature == :child_of))
    |> case do
      nil -> nil
      rel -> rel.target_cwe_id
    end
  end

  defp cwe_name(catalog, id) do
    case catalog[id] do
      %{name: name} -> name
      _ -> "CWE-#{id}"
    end
  end

  defp focus_entry(_catalog, nil), do: nil

  defp focus_entry(catalog, id), do: %{id: "CWE-#{id}", name: cwe_name(catalog, id)}

  # Path from root down to (and including) the focus node, for a breadcrumb.
  defp breadcrumb(_catalog, nil), do: []

  defp breadcrumb(catalog, id) do
    catalog
    |> ancestor_chain(id)
    |> Enum.reverse()
    |> Enum.map(fn node -> %{id: "CWE-#{node}", name: cwe_name(catalog, node)} end)
  end

  defp parse_cwe_id(nil), do: nil
  defp parse_cwe_id("CWE-" <> n), do: String.to_integer(n)
  defp parse_cwe_id(n) when is_integer(n), do: n

  defp parse_cwe_id(other) do
    case Integer.parse(to_string(other)) do
      {n, _} -> n
      :error -> nil
    end
  end

  # ---- donut geometry (pure)

  # Arc path for one slice: outer arc CW, inner arc CCW, closed.
  defp arc_path(center, start_angle, end_angle) do
    large = if end_angle - start_angle > 180, do: 1, else: 0
    {x1, y1} = polar(center, @donut_r_outer, start_angle)
    {x2, y2} = polar(center, @donut_r_outer, end_angle)
    {x3, y3} = polar(center, @donut_r_inner, end_angle)
    {x4, y4} = polar(center, @donut_r_inner, start_angle)

    "M #{x1} #{y1} A #{@donut_r_outer} #{@donut_r_outer} 0 #{large} 1 #{x2} #{y2} " <>
      "L #{x3} #{y3} A #{@donut_r_inner} #{@donut_r_inner} 0 #{large} 0 #{x4} #{y4} Z"
  end

  # A lone 100% slice spans a full circle; an SVG arc with equal start/end
  # points collapses to nothing, so build a proper ring (even-odd filled path
  # of two concentric circles) instead.
  defp full_ring_path(center) do
    circle = fn r ->
      "M #{center - r} #{center} " <>
        "a #{r} #{r} 0 1 0 #{2 * r} 0 a #{r} #{r} 0 1 0 #{-2 * r} 0 Z"
    end

    circle.(@donut_r_outer) <> " " <> circle.(@donut_r_inner)
  end

  defp polar(center, radius, angle_deg) do
    rad = angle_deg * :math.pi() / 180

    {Float.round(center + radius * :math.cos(rad), 2), Float.round(center + radius * :math.sin(rad), 2)}
  end
end
