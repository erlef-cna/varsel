# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecordCweSubtreeCountsTest do
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

  # view 1000, member 707 (pillar); 74 child_of 707; 79 child_of 74.
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
    :ok
  end

  test "counts each CVE once per matching parent, recursively through the subtree" do
    published_record_with_cwes("CVE-#{@year}-2001", [79])
    published_record_with_cwes("CVE-#{@year}-2002", [74])
    published_record_with_cwes("CVE-#{@year}-2003", [707])
    published_record_with_cwes("CVE-#{@year}-2004", [89])

    counts =
      CVE.count_published_cve_records_by_cwe_subtree!(%{view_id: 1000, cwe_ids: [707]},
        actor: nil
      )

    assert counts == [{707, 3}]
  end

  test "count(DISTINCT) — a CVE with two CWEs in the same subtree counts once" do
    published_record_with_cwes("CVE-#{@year}-2005", [79, 74])

    counts =
      CVE.count_published_cve_records_by_cwe_subtree!(%{view_id: 1000, cwe_ids: [707]},
        actor: nil
      )

    assert counts == [{707, 1}]
  end

  test "counts multiple requested parents independently" do
    published_record_with_cwes("CVE-#{@year}-2006", [79])
    published_record_with_cwes("CVE-#{@year}-2007", [74])

    counts =
      CVE.count_published_cve_records_by_cwe_subtree!(%{view_id: 1000, cwe_ids: [79, 74]},
        actor: nil
      )

    assert Enum.sort(counts) == [{74, 2}, {79, 1}]
  end

  test "a parent with zero matching CVEs is absent from the result, not zero" do
    published_record_with_cwes("CVE-#{@year}-2008", [89])

    counts =
      CVE.count_published_cve_records_by_cwe_subtree!(%{view_id: 1000, cwe_ids: [707]},
        actor: nil
      )

    assert counts == []
  end

  test "a wrong view_id matches nothing even if the cwe_id exists in another view" do
    published_record_with_cwes("CVE-#{@year}-2009", [707])

    counts =
      CVE.count_published_cve_records_by_cwe_subtree!(%{view_id: 9999, cwe_ids: [707]},
        actor: nil
      )

    assert counts == []
  end

  describe "count_published_cve_records_in_cwe_view/2" do
    test "with no cwe_id, counts recursively under the whole view (NULL-parent closure)" do
      published_record_with_cwes("CVE-#{@year}-3001", [79])
      published_record_with_cwes("CVE-#{@year}-3002", [707])
      # Outside the view entirely.
      published_record_with_cwes("CVE-#{@year}-3003", [89])

      total =
        CVE.count_published_cve_records_in_cwe_view!(%{view_id: 1000, cwe_id: nil}, actor: nil)

      assert total == 2
    end

    test "count(DISTINCT) — a CVE with two CWEs in the view still counts once toward the total" do
      published_record_with_cwes("CVE-#{@year}-3004", [79, 707])

      total =
        CVE.count_published_cve_records_in_cwe_view!(%{view_id: 1000, cwe_id: nil}, actor: nil)

      assert total == 1
    end

    test "with a cwe_id, counts recursively under that CWE's own subtree only" do
      published_record_with_cwes("CVE-#{@year}-3005", [79])
      published_record_with_cwes("CVE-#{@year}-3006", [707])

      total =
        CVE.count_published_cve_records_in_cwe_view!(%{view_id: 1000, cwe_id: 74}, actor: nil)

      assert total == 1
    end

    test "zero matching CVEs returns 0, not an empty result" do
      total =
        CVE.count_published_cve_records_in_cwe_view!(%{view_id: 1000, cwe_id: nil}, actor: nil)

      assert total == 0
    end

    test "a wrong view_id matches nothing even if the cwe_id exists in another view" do
      published_record_with_cwes("CVE-#{@year}-3007", [707])

      total =
        CVE.count_published_cve_records_in_cwe_view!(%{view_id: 9999, cwe_id: nil}, actor: nil)

      assert total == 0
    end
  end
end
