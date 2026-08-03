# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0
defmodule Varsel.Cases.Case.Changes.AdoptCveRecordTest do
  @moduledoc """
  Adopting an existing CVE record into a case: the record it links, the content
  it carries over, the children it creates, and the rules that stop it being
  done twice or by the wrong actor.
  """

  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Cases.Case
  alias Varsel.Cases.Validations.CveRecordAdoptable
  alias Varsel.CVE.CveRecord
  alias Varsel.Fixtures

  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
  @cve_id "CVE-2026-31337"

  setup do
    Fixtures.seed_weakness(200, "Exposure of Sensitive Information")
    Fixtures.seed_attack_pattern(116, "Excavation")

    %{
      poc: Fixtures.register_user("adopt_poc", :poc),
      supporter: Fixtures.register_user("adopt_supporter", :supporter)
    }
  end

  defp legacy_record(cna_overrides \\ %{}) do
    cna =
      Map.merge(
        %{
          "title" => "Information disclosure in acme_lib",
          "source" => %{"discovery" => "EXTERNAL"},
          "datePublic" => "2026-01-15T09:30:00.000Z",
          "metrics" => [%{"cvssV4_0" => %{"vectorString" => @vector}}],
          "problemTypes" => [%{"descriptions" => [%{"cweId" => "CWE-200", "type" => "CWE"}]}],
          "impacts" => [%{"capecId" => "CAPEC-116"}],
          "credits" => [%{"lang" => "en", "type" => "finder", "value" => "A Finder / EEF"}],
          "references" => [
            %{"tags" => ["vendor-advisory"], "url" => "https://example.com/advisory"}
          ]
        },
        cna_overrides
      )

    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{"cveId" => @cve_id, "state" => "PUBLISHED"},
      "containers" => %{"cna" => cna}
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  describe "adopting a record" do
    test "opens a draft case linked to the record", %{poc: poc} do
      record = legacy_record()

      case_record = Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      assert case_record.state == :draft
      assert case_record.cve_record_id == record.id
      assert Ash.load!(case_record, [:cve_id], actor: poc).cve_id == @cve_id
    end

    test "carries the record's own fields over", %{poc: poc} do
      record = legacy_record()

      case_record = Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      assert case_record.title == "Information disclosure in acme_lib"
      assert case_record.discovery == :external
      assert case_record.date_public == ~U[2026-01-15 09:30:00Z]
      assert case_record.cvss_v4.vector == @vector
      assert case_record.cvss_v4.version == :v4
    end

    test "creates the CWE, CAPEC, credit and reference rows", %{poc: poc} do
      record = legacy_record()

      case_record =
        %{cve_record_id: record.id}
        |> Cases.adopt_cve_record!(actor: poc)
        |> Ash.load!([:weaknesses, :impacts, :credits, :references], actor: poc)

      assert [%{cwe_id: 200}] = case_record.weaknesses
      assert [%{capec_id: 116}] = case_record.impacts

      assert [%{name: "A Finder", organization: "EEF", credit_type: :finder}] =
               case_record.credits

      assert [%{url: "https://example.com/advisory", tags: ["vendor-advisory"]}] =
               case_record.references
    end

    test "assigns the adopting POC to the case", %{poc: poc} do
      record = legacy_record()

      case_record =
        %{cve_record_id: record.id}
        |> Cases.adopt_cve_record!(actor: poc)
        |> Ash.load!([:assignments], actor: poc)

      assert [%{user_id: user_id}] = case_record.assignments
      assert user_id == poc.id
    end

    test "leaves the CVE record in the state it was in", %{poc: poc} do
      record = legacy_record()

      Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      assert Ash.reload!(record, authorize?: false).state == :published
    end

    test "leaves out affected packages and a pre-v4 score", %{poc: poc} do
      record =
        legacy_record(%{
          "affected" => [%{"packageName" => "acme_lib", "vendor" => "acme"}],
          "descriptions" => [%{"lang" => "en", "value" => "Plain text only."}],
          "metrics" => [
            %{"cvssV3_1" => %{"vectorString" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
          ]
        })

      case_record = Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      # Prose does come over — as the plain text, for a human to tidy up.
      assert case_record.description_md == "Plain text only."
      assert case_record.cvss_v4 == nil
      assert Ash.load!(case_record, [:affected_packages], actor: poc).affected_packages == []
    end

    test "a CWE the local catalog has never synced is skipped, not fatal", %{poc: poc} do
      record =
        legacy_record(%{
          "problemTypes" => [
            %{"descriptions" => [%{"cweId" => "CWE-200"}]},
            %{"descriptions" => [%{"cweId" => "CWE-999999"}]}
          ]
        })

      case_record = Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      assert [%{cwe_id: 200}] = Ash.load!(case_record, [:weaknesses], actor: poc).weaknesses
    end

    test "a record with a bare CNA container still adopts", %{poc: poc} do
      record = Fixtures.published_cve_record("CVE-2026-40404", "Bare record")

      case_record = Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      assert case_record.title == "Bare record"
      assert case_record.state == :draft
      assert case_record.discovery == :unknown
      assert case_record.timeline == []
    end
  end

  describe "rules" do
    test "a record can only be adopted once", %{poc: poc} do
      record = legacy_record()
      Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      assert {:error, %Invalid{} = error} =
               Cases.adopt_cve_record(%{cve_record_id: record.id}, actor: poc)

      assert Exception.message(error) =~ "already has a case"
    end

    test "a reserved record has nothing to manage as a case", %{poc: poc} do
      record = Fixtures.reserved_cve_record("CVE-2026-50505")

      assert {:error, %Invalid{} = error} =
               Cases.adopt_cve_record(%{cve_record_id: record.id}, actor: poc)

      assert Exception.message(error) =~ "nothing to manage as a case"
    end

    test "a supporter cannot adopt a record", %{poc: poc, supporter: supporter} do
      record = legacy_record()

      assert {:error, %Forbidden{}} =
               Cases.adopt_cve_record(%{cve_record_id: record.id}, actor: supporter)

      # And the affordance is not offered to them either.
      refute Ash.can?({Case, :adopt_cve_record}, supporter)
      assert Ash.can?({Case, :adopt_cve_record}, poc)
    end

    # The list page splits this question in two for the sake of one query per
    # page rather than one per row (see VarselWeb.CveListLive.adoptable?/1);
    # asking it whole still has to work, and is what any other caller gets.
    test "can_adopt_cve_record? sees the validation, not just the policy", %{poc: poc} do
      record = legacy_record()

      assert Cases.can_adopt_cve_record?(poc, %{cve_record_id: record.id}, validate?: true)

      Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)

      refute Cases.can_adopt_cve_record?(poc, %{cve_record_id: record.id}, validate?: true)
    end

    test "a reserved record is not adoptable by can?, matching adoptable_states", %{poc: poc} do
      record = Fixtures.reserved_cve_record("CVE-2026-60606")

      refute Cases.can_adopt_cve_record?(poc, %{cve_record_id: record.id}, validate?: true)
      refute record.state in CveRecordAdoptable.adoptable_states()
    end
  end
end
