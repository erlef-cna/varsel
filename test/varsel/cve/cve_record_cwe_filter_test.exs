# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecordCweFilterTest do
  use Varsel.DataCase, async: false

  alias Varsel.CVE
  alias Varsel.CVE.CveRecord
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.WeaknessRelationship
  alias Varsel.Fixtures

  @year Date.utc_today().year

  defp published_record_with_cwes(cve_id, cwe_ids) do
    problem_types =
      case cwe_ids do
        [] ->
          []

        ids ->
          [
            %{
              "descriptions" =>
                Enum.map(ids, fn cwe_id ->
                  %{
                    "cweId" => "CWE-#{cwe_id}",
                    "description" => "CWE-#{cwe_id}",
                    "lang" => "en",
                    "type" => "CWE"
                  }
                end)
            }
          ]
      end

    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{"cveId" => cve_id, "state" => "PUBLISHED"},
      "containers" => %{
        "cna" => %{
          "title" => "#{cve_id} title",
          "problemTypes" => problem_types
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json},
      action: :import,
      authorize?: false,
      load: [:cve_id]
    )
  end

  # view 1000, member 707 (pillar); 74 child_of 707; 79 child_of 74 — the same
  # ids used in weakness_test.exs, for familiarity.
  defp seed_closure do
    Fixtures.seed_weakness(707, "Improper Neutralization")
    Fixtures.seed_weakness(74, "Injection")
    Fixtures.seed_weakness(79, "XSS")
    Fixtures.seed_view(1000, "Research Concepts")

    Ash.Seed.seed!(ViewMembership, %{view_id: 1000, cwe_id: 707})

    Ash.Seed.seed!(WeaknessRelationship, %{
      source_cwe_id: 74,
      target_cwe_id: 707,
      nature: :child_of,
      view_id: 1000
    })

    Ash.Seed.seed!(WeaknessRelationship, %{
      source_cwe_id: 79,
      target_cwe_id: 74,
      nature: :child_of,
      view_id: 1000
    })

    Varsel.Repo.query!("REFRESH MATERIALIZED VIEW cwe_weakness_closure")
  end

  setup do
    seed_closure()

    descendant = published_record_with_cwes("CVE-#{@year}-1001", [79])
    ancestor = published_record_with_cwes("CVE-#{@year}-1002", [707])
    out_of_view = published_record_with_cwes("CVE-#{@year}-1003", [89])
    no_cwe = published_record_with_cwes("CVE-#{@year}-1004", [])

    %{descendant: descendant, ancestor: ancestor, out_of_view: out_of_view, no_cwe: no_cwe}
  end

  defp cve_ids(records), do: records |> Enum.map(& &1.cve_id) |> Enum.sort()

  test "no args returns all published records unchanged", %{
    descendant: descendant,
    ancestor: ancestor,
    out_of_view: out_of_view,
    no_cwe: no_cwe
  } do
    records = CveRecord |> Ash.Query.for_read(:list_published, %{}) |> Ash.read!(authorize?: true)

    assert cve_ids(records) ==
             cve_ids([descendant, ancestor, out_of_view, no_cwe])
  end

  test "cwe_id: 79 matches only the direct CWE-79 record", %{descendant: descendant} do
    records =
      CveRecord
      |> Ash.Query.for_read(:list_published, %{cwe_id: 79})
      |> Ash.read!(authorize?: true)

    assert cve_ids(records) == cve_ids([descendant])
  end

  test "cwe_id: 707 matches only the direct CWE-707 record (direct, not recursive)", %{
    ancestor: ancestor
  } do
    records =
      CveRecord
      |> Ash.Query.for_read(:list_published, %{cwe_id: 707})
      |> Ash.read!(authorize?: true)

    assert cve_ids(records) == cve_ids([ancestor])
  end

  test "cwe_id: 707 + view_id: 1000 matches the whole subtree (707 and its descendant 79)", %{
    descendant: descendant,
    ancestor: ancestor
  } do
    records =
      CveRecord
      |> Ash.Query.for_read(:list_published, %{cwe_id: 707, view_id: 1000})
      |> Ash.read!(authorize?: true)

    assert cve_ids(records) == cve_ids([descendant, ancestor])
  end

  test "view_id: 1000 alone matches every record with any CWE in the view", %{
    descendant: descendant,
    ancestor: ancestor
  } do
    records =
      CveRecord
      |> Ash.Query.for_read(:list_published, %{view_id: 1000})
      |> Ash.read!(authorize?: true)

    assert cve_ids(records) == cve_ids([descendant, ancestor])
  end

  test "cwe_id with a wrong view_id returns nothing" do
    records =
      CveRecord
      |> Ash.Query.for_read(:list_published, %{cwe_id: 707, view_id: 9999})
      |> Ash.read!(authorize?: true)

    assert records == []
  end

  test "args flow through the public code interface", %{descendant: descendant} do
    records = CVE.list_published_cve_records!(%{cwe_id: 79}, actor: nil)

    assert cve_ids(records) == cve_ids([descendant])
  end
end
