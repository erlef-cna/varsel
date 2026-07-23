# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ProposalSpecializedTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Cases.Proposal
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("specialized_poc", :poc)
    case_record = Fixtures.open_case(poc, %{title: "Original title"})

    %{poc: poc, case: case_record}
  end

  describe "set actions" do
    test "propose_title sets field_name + envelope", %{poc: poc, case: case_record} do
      proposal =
        Cases.propose_title!(%{case_id: case_record.id, value: "Better title"}, actor: poc)

      assert proposal.target == :case
      assert proposal.operation == :set
      assert proposal.field_name == "title"
      assert proposal.proposed_value == %{"value" => "Better title"}
      assert proposal.author_id == poc.id
    end

    test "propose_workarounds targets the right field", %{poc: poc, case: case_record} do
      proposal =
        Cases.propose_workarounds!(%{case_id: case_record.id, value: "disable ssh"}, actor: poc)

      assert proposal.field_name == "workarounds_md"
      assert proposal.proposed_value == %{"value" => "disable ssh"}
    end

    test "propose_cvss casts the vector through the real type", %{poc: poc, case: case_record} do
      vector = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"

      proposal = Cases.propose_cvss!(%{case_id: case_record.id, value: vector}, actor: poc)

      assert proposal.field_name == "cvss_v4"
      # The envelope stores the plain vector string (not the dumped CVSS map);
      # score/severity/version are derived when it re-casts on accept.
      assert proposal.proposed_value["value"] == vector

      accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)
      case_record = Ash.get!(Cases.Case, accepted.case_id, authorize?: false)
      assert case_record.cvss_v4.vector == vector
    end

    test "propose_cvss rejects a malformed vector at the argument layer", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, _error} =
               Cases.propose_cvss(%{case_id: case_record.id, value: "not-a-vector"}, actor: poc)
    end

    test "propose_discovery rejects a bad enum at the argument layer", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, _error} =
               Cases.propose_discovery(
                 %{case_id: case_record.id, value: "not_a_discovery"},
                 actor: poc
               )
    end
  end

  describe "insert actions" do
    test "propose_credit packs the credit payload", %{poc: poc, case: case_record} do
      proposal =
        Cases.propose_credit!(
          %{case_id: case_record.id, name: "Jane Doe", credit_type: :finder},
          actor: poc
        )

      assert proposal.target == :credit
      assert proposal.operation == :insert
      assert is_nil(proposal.field_name)

      # Enum atoms serialize to strings in the JSON envelope.
      assert proposal.proposed_value == %{
               "value" => %{"name" => "Jane Doe", "credit_type" => "finder"}
             }
    end

    test "propose_weakness carries only cwe_id", %{poc: poc, case: case_record} do
      proposal = Cases.propose_weakness!(%{case_id: case_record.id, cwe_id: 79}, actor: poc)

      assert proposal.target == :weakness
      assert proposal.proposed_value == %{"value" => %{"cwe_id" => 79}}
    end

    test "propose_impact carries only capec_id", %{poc: poc, case: case_record} do
      proposal = Cases.propose_impact!(%{case_id: case_record.id, capec_id: 66}, actor: poc)

      assert proposal.target == :impact
      assert proposal.proposed_value == %{"value" => %{"capec_id" => 66}}
    end

    test "propose_reference omits the nil tags argument", %{poc: poc, case: case_record} do
      proposal =
        Cases.propose_reference!(
          %{case_id: case_record.id, url: "https://example.com/advisory"},
          actor: poc
        )

      assert proposal.target == :reference
      assert proposal.proposed_value == %{"value" => %{"url" => "https://example.com/advisory"}}
    end

    test "propose_reference keeps supplied tags", %{poc: poc, case: case_record} do
      proposal =
        Cases.propose_reference!(
          %{
            case_id: case_record.id,
            url: "https://example.com/advisory",
            tags: ["vendor-advisory"]
          },
          actor: poc
        )

      assert proposal.proposed_value["value"]["tags"] == ["vendor-advisory"]
    end

    test "propose_version_event addresses a package via target_id", %{
      poc: poc,
      case: case_record
    } do
      package = Fixtures.add_affected_package(poc, case_record)
      sha = String.duplicate("a", 40)

      proposal =
        Cases.propose_version_event!(
          %{case_id: case_record.id, target_id: package.id, event: :fixed, commit_sha: sha},
          actor: poc
        )

      assert proposal.target == :version_event
      assert proposal.target_id == package.id
      assert proposal.proposed_value == %{"value" => %{"event" => "fixed", "commit_sha" => sha}}
    end

    test "propose_package_channel addresses a package via target_id", %{
      poc: poc,
      case: case_record
    } do
      package = Fixtures.add_affected_package(poc, case_record)

      proposal =
        Cases.propose_package_channel!(
          %{case_id: case_record.id, target_id: package.id, purl_type: :hex, name: "acme_lib"},
          actor: poc
        )

      assert proposal.target == :package_channel
      assert proposal.target_id == package.id

      assert proposal.proposed_value == %{
               "value" => %{"purl_type" => "hex", "name" => "acme_lib"}
             }
    end

    test "propose_affected_package packs vendor/product", %{poc: poc, case: case_record} do
      proposal =
        Cases.propose_affected_package!(
          %{case_id: case_record.id, vendor: "acme", product: "acme_lib"},
          actor: poc
        )

      assert proposal.target == :affected_package

      assert proposal.proposed_value == %{
               "value" => %{"vendor" => "acme", "product" => "acme_lib"}
             }
    end
  end

  describe "preset insert actions" do
    test "propose_otp_affected_package carries a preset payload", %{poc: poc, case: case_record} do
      sha = String.duplicate("a", 40)

      proposal =
        Cases.propose_otp_affected_package!(
          %{case_id: case_record.id, applications: ["ssh"], introduced_commit: sha},
          actor: poc
        )

      assert proposal.target == :affected_package
      payload = proposal.proposed_value["value"]
      # Stored through the :map attribute, the preset atom round-trips as a string.
      assert payload["preset"] == "otp"
      assert payload["applications"] == ["ssh"]
      assert payload["introduced_commit"] == sha
    end

    test "propose_gleam_affected_package needs no applications", %{poc: poc, case: case_record} do
      sha = String.duplicate("b", 40)

      proposal =
        Cases.propose_gleam_affected_package!(
          %{case_id: case_record.id, introduced_commit: sha},
          actor: poc
        )

      payload = proposal.proposed_value["value"]
      assert payload["preset"] == "gleam"
      refute Map.has_key?(payload, "applications")
    end
  end

  describe "propose_delete" do
    test "stamps the runtime target and packs no payload", %{poc: poc, case: case_record} do
      package = Fixtures.add_affected_package(poc, case_record)

      proposal =
        Cases.propose_delete!(
          %{case_id: case_record.id, target: :affected_package, target_id: package.id},
          actor: poc
        )

      assert proposal.target == :affected_package
      assert proposal.operation == :delete
      assert proposal.target_id == package.id
      assert is_nil(proposal.proposed_value)
    end

    test "an accepted delete removes the row", %{poc: poc, case: case_record} do
      package = Fixtures.add_affected_package(poc, case_record)

      proposal =
        Cases.propose_delete!(
          %{case_id: case_record.id, target: :affected_package, target_id: package.id},
          actor: poc
        )

      Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      assert {:error, _} = Ash.get(Cases.AffectedPackage, package.id, authorize?: false)
    end
  end

  test "accepting a typed insert creates the row", %{poc: poc, case: case_record} do
    proposal =
      Cases.propose_reference!(
        %{case_id: case_record.id, url: "https://example.com/advisory", tags: ["patch"]},
        actor: poc
      )

    accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)

    reference = Ash.get!(Cases.CaseReference, accepted.applied_target_id, authorize?: false)
    assert reference.url == "https://example.com/advisory"
    assert reference.case_id == case_record.id
    assert %Proposal{state: :accepted} = accepted
  end
end
