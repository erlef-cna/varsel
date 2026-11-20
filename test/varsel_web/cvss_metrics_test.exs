# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CvssMetricsTest do
  use ExUnit.Case, async: true

  alias VarselWeb.CvssMetrics

  defp values(vector) do
    {:ok, %{version: version, groups: groups}} = CvssMetrics.breakdown(vector)
    {version, Enum.map(groups, &{&1.title, Enum.map(&1.metrics, fn m -> {m.name, m.value} end)})}
  end

  test "reads a v4.0 vector into its three groups, base metrics only" do
    assert values("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:H/SC:H/SI:N/SA:N/E:P") ==
             {"4.0",
              [
                {"Exploitability",
                 [
                   {"Attack Vector", "Network"},
                   {"Attack Complexity", "Low"},
                   {"Attack Requirements", "Present"},
                   {"Privileges Required", "None"},
                   {"User Interaction", "Active"}
                 ]},
                {"Vulnerable System", [{"Confidentiality", "None"}, {"Integrity", "Low"}, {"Availability", "High"}]},
                {"Subsequent Systems", [{"Confidentiality", "High"}, {"Integrity", "None"}, {"Availability", "None"}]}
              ]}
  end

  test "reads v3.1 and v3.0 vectors, scope with the impact" do
    for version <- ["3.1", "3.0"] do
      assert values("CVSS:#{version}/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:L") ==
               {version,
                [
                  {"Exploitability",
                   [
                     {"Attack Vector", "Adjacent"},
                     {"Attack Complexity", "High"},
                     {"Privileges Required", "Low"},
                     {"User Interaction", "Required"}
                   ]},
                  {"Impact",
                   [
                     {"Scope", "Changed"},
                     {"Confidentiality", "High"},
                     {"Integrity", "None"},
                     {"Availability", "Low"}
                   ]}
                ]}
    end
  end

  test "every value carries its meaning" do
    {:ok, %{groups: groups}} =
      CvssMetrics.breakdown("CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:L/VI:H/VA:N/SC:L/SI:L/SA:H")

    assert groups
           |> Enum.flat_map(& &1.metrics)
           |> Enum.all?(&(is_binary(&1.meaning) and &1.meaning != ""))
  end

  test "refuses what is not a complete v3.0, v3.1 or v4.0 base vector" do
    for vector <- [
          nil,
          "",
          "CVSS:4.0/bogus",
          "CVSS:4.0/AV:N/AC:L",
          "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
          "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:N",
          "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        ] do
      assert CvssMetrics.breakdown(vector) == :error
    end
  end

  test "changes lists the base metrics that differ, in order" do
    assert CvssMetrics.changes(
             "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
             "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N/E:A"
           ) == [
             %{group: "Exploitability", name: "Attack Complexity", old: "Low", new: "High"},
             %{group: "Exploitability", name: "Attack Requirements", old: "None", new: "Present"},
             %{group: "Vulnerable System", name: "Confidentiality", old: "None", new: "High"}
           ]
  end

  test "changes is empty across versions or for an unreadable side" do
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"

    assert CvssMetrics.changes(v4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == []
    assert CvssMetrics.changes(nil, v4) == []

    assert CvssMetrics.changes("Crash on malformed input.", "A remote attacker crashes the node.") ==
             []
  end
end
