# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ReadinessTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseMetric
  alias Varsel.Cases.Readiness

  defp status(section, case_fields) do
    %Case{
      references: [],
      derived_references: [],
      affected_packages: [],
      credits: [],
      weaknesses: [],
      impacts: [],
      metrics: []
    }
    |> Map.merge(case_fields)
    |> Readiness.sections()
    |> Enum.find(&(&1.id == section))
    |> Map.fetch!(:status)
  end

  defp references_status(references, derived_references) do
    status("references", %{references: references, derived_references: derived_references})
  end

  test "severity needs attention without a GENERAL scenario" do
    assert status("severity", %{metrics: []}) == :attention
    assert status("severity", %{metrics: [%CaseMetric{scenario: "Local attacker"}]}) == :attention
  end

  test "a GENERAL scenario makes severity ready" do
    metrics = [%CaseMetric{scenario: "Local attacker"}, %CaseMetric{scenario: "GENERAL"}]
    assert status("severity", %{metrics: metrics}) == :ok
  end

  test "references need attention when the record would ship none" do
    assert references_status([], []) == :attention
  end

  test "a derived reference alone makes references ready" do
    assert references_status([], [%{"url" => "https://osv.dev/vulnerability/EEF-CVE-2026-0001"}]) ==
             :ok
  end

  test "a manual reference alone makes references ready" do
    assert references_status([%{url: "https://example.com/fix"}], []) == :ok
  end
end
