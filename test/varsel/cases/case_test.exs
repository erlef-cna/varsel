# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.CVE.CveRecord
  alias Varsel.Fixtures

  setup do
    %{
      poc: Fixtures.register_user("case_poc", :poc),
      supporter: Fixtures.register_user("case_supporter", :supporter)
    }
  end

  describe ":open" do
    test "a POC opens a draft case", %{poc: poc} do
      case_record = Cases.open_case!(%{title: "SSH bug", description_md: "Bad."}, actor: poc)

      assert case_record.state == :draft
      assert case_record.title == "SSH bug"
      assert case_record.discovery == :unknown
    end

    test "a supporter cannot open cases", %{supporter: supporter} do
      assert {:error, %Forbidden{}} =
               Cases.open_case(%{title: "nope"}, actor: supporter)
    end

    test "an invalid CVSS vector is rejected", %{poc: poc} do
      assert {:error, error} =
               Cases.open_case(%{title: "x", cvss_v4: "CVSS:4.0/bogus"}, actor: poc)

      assert Exception.message(error) =~ "cvss"
    end
  end

  describe "read scoping" do
    test "POCs see every case, supporters only assigned ones", %{poc: poc, supporter: supporter} do
      assigned = Fixtures.open_case(poc, %{title: "assigned"})
      _other = Fixtures.open_case(poc, %{title: "other"})

      Cases.assign_case_user!(%{case_id: assigned.id, user_id: supporter.id}, actor: poc)

      assert length(Cases.list_cases!(actor: poc)) == 2
      assert [%{title: "assigned"}] = Cases.list_cases!(actor: supporter)
    end
  end

  describe ":edit / content freeze" do
    test "content is editable in draft and review", %{poc: poc} do
      case_record = Fixtures.open_case(poc)

      case_record = Cases.edit_case!(case_record, %{description_md: "In draft."}, actor: poc)
      case_record = Cases.request_case_review!(case_record, actor: poc)
      case_record = Cases.edit_case!(case_record, %{description_md: "In review."}, actor: poc)

      assert case_record.description_md == "In review."
    end

    test "rejects markdown content over the length cap", %{poc: poc} do
      case_record = Fixtures.open_case(poc)
      oversized = String.duplicate("x", 60_000)

      assert {:error, error} =
               Cases.edit_case(case_record, %{description_md: oversized}, actor: poc)

      assert Exception.message(error) =~ "length must be less than or equal to"
    end

    test "content is frozen from approved onward", %{poc: poc} do
      case_record = Fixtures.open_case(poc)
      case_record = Cases.request_case_review!(case_record, actor: poc)
      case_record = Cases.approve_case!(case_record, actor: poc)

      assert {:error, error} = Cases.edit_case(case_record, %{title: "nope"}, actor: poc)
      assert Exception.message(error) =~ "frozen"
    end

    test "an assigned supporter can edit; an unassigned one cannot", %{
      poc: poc,
      supporter: supporter
    } do
      case_record = Fixtures.open_case(poc)

      assert {:error, %Forbidden{}} =
               Cases.edit_case(case_record, %{title: "nope"}, actor: supporter)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      assert %{title: "yes"} = Cases.edit_case!(case_record, %{title: "yes"}, actor: supporter)
    end

    test "child rows follow the same freeze", %{poc: poc} do
      case_record = Fixtures.open_case(poc)
      package = Fixtures.add_affected_package(poc, case_record)

      case_record = Cases.request_case_review!(case_record, actor: poc)
      _case_record = Cases.approve_case!(case_record, actor: poc)

      assert {:error, error} = Cases.edit_affected_package(package, %{vendor: "nope"}, actor: poc)
      assert Exception.message(error) =~ "frozen"

      assert {:error, error} =
               Cases.add_case_reference(
                 %{case_id: case_record.id, url: "https://example.com/advisory"},
                 actor: poc
               )

      assert Exception.message(error) =~ "frozen"
    end
  end

  describe "lifecycle transitions" do
    test "request_changes and reopen return to draft", %{poc: poc} do
      case_record = Fixtures.open_case(poc)
      case_record = Cases.request_case_review!(case_record, actor: poc)
      case_record = Cases.request_case_changes!(case_record, actor: poc)
      assert case_record.state == :draft

      case_record = Cases.request_case_review!(case_record, actor: poc)
      case_record = Cases.approve_case!(case_record, actor: poc)
      case_record = Cases.reopen_case!(case_record, actor: poc)
      assert case_record.state == :draft
    end

    test "a supporter cannot approve", %{poc: poc, supporter: supporter} do
      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      case_record = Cases.request_case_review!(case_record, actor: supporter)

      assert {:error, %Forbidden{}} = Cases.approve_case(case_record, actor: supporter)
    end
  end

  describe ":assign_cve_id" do
    test "assigns the lowest free reserved ID of the current year", %{poc: poc} do
      year = Date.utc_today().year
      Fixtures.reserved_cve_record("CVE-#{year}-11111")
      Fixtures.reserved_cve_record("CVE-#{year}-9999")

      case_record = Fixtures.open_case(poc)
      case_record = Cases.assign_case_cve_id!(case_record, %{}, actor: poc)

      case_record = Ash.load!(case_record, :cve_id, authorize?: false)
      assert case_record.cve_id == "CVE-#{year}-9999"

      cve_record = Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false)
      assert cve_record.state == :draft
    end

    test "refuses a second assignment", %{poc: poc} do
      year = Date.utc_today().year
      Fixtures.reserved_cve_record("CVE-#{year}-11112")
      Fixtures.reserved_cve_record("CVE-#{year}-11113")

      case_record = Fixtures.open_case(poc)
      case_record = Cases.assign_case_cve_id!(case_record, %{}, actor: poc)

      assert {:error, error} = Cases.assign_case_cve_id(case_record, %{}, actor: poc)
      assert Exception.message(error) =~ "already has a CVE ID"
    end

    test "errors when the pool is empty", %{poc: poc} do
      case_record = Fixtures.open_case(poc)

      assert {:error, error} = Cases.assign_case_cve_id(case_record, %{}, actor: poc)
      assert Exception.message(error) =~ "no reserved CVE IDs"
    end
  end

  describe "cvss_score / severity_bucket calculations" do
    @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

    test "reads the score and bucket off the already-scored CVSS struct", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{cvss_v4: @vector})
      case_record = Ash.load!(case_record, [:cvss_score, :severity_bucket], authorize?: false)

      assert case_record.cvss_score == 8.7
      assert case_record.severity_bucket == :high
    end

    test "both calculations are nil when the case has no CVSS vector yet", %{poc: poc} do
      case_record = Fixtures.open_case(poc)
      case_record = Ash.load!(case_record, [:cvss_score, :severity_bucket], authorize?: false)

      assert case_record.cvss_score == nil
      assert case_record.severity_bucket == nil
    end
  end

  describe ":close" do
    test "closes a case without a CVE ID", %{poc: poc} do
      case_record = Fixtures.open_case(poc)

      case_record =
        Cases.close_case!(case_record, %{closed_reason: "not a vulnerability"}, actor: poc)

      assert case_record.state == :closed
      assert case_record.closed_reason == "not a vulnerability"
    end

    test "requires an explicit decision when a CVE ID is assigned", %{poc: poc} do
      year = Date.utc_today().year
      Fixtures.reserved_cve_record("CVE-#{year}-11120")

      case_record = Fixtures.open_case(poc)
      case_record = Cases.assign_case_cve_id!(case_record, %{}, actor: poc)

      assert {:error, error} = Cases.close_case(case_record, %{}, actor: poc)
      assert Exception.message(error) =~ "reject_cve_id"

      case_record = Cases.close_case!(case_record, %{acknowledge_parked_cve_id: true}, actor: poc)
      assert case_record.state == :closed
    end

    test "reject_cve_id burns the ID at MITRE", %{poc: poc} do
      year = Date.utc_today().year
      Fixtures.reserved_cve_record("CVE-#{year}-11121")

      Req.Test.stub(Varsel.CVE.MitreCveApi, fn conn ->
        Req.Test.json(conn, %{"message" => "CVE ID rejected"})
      end)

      case_record = Fixtures.open_case(poc)
      case_record = Cases.assign_case_cve_id!(case_record, %{}, actor: poc)

      case_record =
        Cases.close_case!(case_record, %{reject_cve_id: true, closed_reason: "duplicate"}, actor: poc)

      assert case_record.state == :closed
      assert Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false).state == :rejected
    end

    test "sweeps open proposals", %{poc: poc} do
      case_record = Fixtures.open_case(poc)

      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :case,
            operation: :set,
            field_name: "title",
            proposed_value: %{"value" => "Better title"}
          },
          actor: poc
        )

      Cases.close_case!(case_record, %{}, actor: poc)

      proposal = Ash.get!(Cases.Proposal, proposal.id, authorize?: false)
      assert proposal.state == :superseded
      assert proposal.resolution_note =~ "closed"
    end
  end
end
