# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ChartsTest do
  use ExUnit.Case, async: true

  alias VarselWeb.Charts

  @now ~U[2025-08-15 00:00:00Z]

  @dates [
    ~U[2025-01-10 00:00:00Z],
    ~U[2025-02-01 00:00:00Z],
    ~U[2025-05-16 00:00:00Z],
    ~U[2025-06-16 00:00:00Z],
    ~U[2025-06-20 00:00:00Z],
    ~U[2025-07-20 00:00:00Z],
    ~U[2025-08-01 00:00:00Z]
  ]

  describe "build_points/2" do
    test "aggregates by quarter with a leading zero quarter and a forecast tail" do
      %{points: points, y_max: y_max} = Charts.build_points(@dates, @now)

      labels = Enum.map(points, & &1.label)
      assert labels == ["Q4 2024", "Q1 2025", "Q2 2025", "Q3 2025", "Q4 2025"]
      assert y_max >= 3

      assert List.first(points).count == 0
      assert Enum.find(points, &(&1.label == "Q1 2025")).count == 2
      assert Enum.find(points, &(&1.label == "Q2 2025")).count == 3
    end

    test "marks the current quarter with a projection and the next quarter as a forecast" do
      %{points: points} = Charts.build_points(@dates, @now)

      current = Enum.find(points, &(&1.kind == :current))
      assert current.label == "Q3 2025"
      assert current.count == 2
      assert Map.has_key?(current, :projected)

      forecast = Enum.find(points, &(&1.kind == :next))
      assert forecast.label == "Q4 2025"
    end

    test "handles an empty dataset" do
      %{points: points} = Charts.build_points([], @now)
      current = Enum.find(points, &(&1.kind == :current))
      assert current.count == 0
    end
  end

  describe "cve_activity_data_from/2" do
    test "computes geometry with a projection for the current quarter" do
      data = Charts.cve_activity_data_from(@dates, @now)

      assert data.view_box =~ "0 0 700"
      assert [%{value: 0} | _] = data.ticks
      # solid line + area cover the confirmed points.
      assert data.solid.line =~ ~r/\d+,\d+/
      assert data.solid.area =~ "Z"
      # projection: triangle to the projected dot + extrapolation to next quarter.
      assert data.projection.triangle
      assert data.projection.extrapolation
      # current-quarter point carries the elapsed fraction.
      assert Enum.find(data.points, &(&1.kind == :current)).elapsed >= 0.0
    end
  end

  describe "ChartComponents.cve_activity_chart/1" do
    import Phoenix.LiveViewTest

    test "renders an accessible svg with dot popovers and a legend" do
      data = Charts.cve_activity_data_from(@dates, @now)
      svg = render_component(&VarselWeb.ChartComponents.cve_activity_chart/1, data: data)

      assert svg =~ "<svg"
      assert svg =~ ~s(role="img")
      assert svg =~ "chart-dot-group"
      assert svg =~ "Q3"
      assert svg =~ "Actual CVEs"
      assert svg =~ "Projected / Forecast"
      # elapsed % appears in the current-quarter popover.
      assert svg =~ "% of quarter elapsed"
    end
  end
end
