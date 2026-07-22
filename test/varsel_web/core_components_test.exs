# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CoreComponentsTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias VarselWeb.CoreComponents

  describe "severity_bucket/1" do
    test "buckets exactly 0.0 as :none, never :low" do
      assert CoreComponents.severity_bucket(0.0) == :none
    end

    test "buckets the low/medium/high/critical ranges" do
      assert CoreComponents.severity_bucket(0.1) == :low
      assert CoreComponents.severity_bucket(3.9) == :low
      assert CoreComponents.severity_bucket(4.0) == :medium
      assert CoreComponents.severity_bucket(6.9) == :medium
      assert CoreComponents.severity_bucket(7.0) == :high
      assert CoreComponents.severity_bucket(8.9) == :high
      assert CoreComponents.severity_bucket(9.0) == :critical
      assert CoreComponents.severity_bucket(10.0) == :critical
    end
  end

  describe "severity_chip/1" do
    test "renders the compact initial + score by default" do
      html = render_component(&CoreComponents.severity_chip/1, score: 9.1)
      assert html =~ "C 9.1"
    end

    test "renders the full rating word when variant: :full" do
      html = render_component(&CoreComponents.severity_chip/1, score: 9.1, variant: :full)
      assert html =~ "CRITICAL 9.1"
    end

    test "renders a dashed no-score chip when score is nil, distinct from NONE" do
      html = render_component(&CoreComponents.severity_chip/1, score: nil)
      assert html =~ "no score"
      refute html =~ "sev-none"
    end

    test "a real 0.0 renders the grey NONE chip, not the no-score chip" do
      html = render_component(&CoreComponents.severity_chip/1, score: 0.0, variant: :full)
      assert html =~ "NONE 0.0"
      refute html =~ "no score"
    end

    test "critical is the only filled chip (uses the critical fill token)" do
      critical = render_component(&CoreComponents.severity_chip/1, score: 9.5)
      high = render_component(&CoreComponents.severity_chip/1, score: 8.0)

      assert critical =~ "sev-critical-fill"
      refute high =~ "sev-critical-fill"
    end
  end
end
