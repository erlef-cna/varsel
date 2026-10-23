# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ReadinessTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Case
  alias Varsel.Cases.Readiness

  defp references_status(references, derived_references) do
    %Case{
      references: references,
      derived_references: derived_references,
      affected_packages: [],
      credits: [],
      weaknesses: [],
      impacts: []
    }
    |> Readiness.sections()
    |> Enum.find(&(&1.id == "references"))
    |> Map.fetch!(:status)
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
