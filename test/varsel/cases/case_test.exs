# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Changes.StaleRecord
  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.CVE.CveRecord
  alias Varsel.Fixtures

  setup do
    %{
      poc: Fixtures.register_user("case_poc", :poc),
      supporter: Fixtures.register_user("case_supporter", :supporter),
      collaborator: Fixtures.register_user("case_collaborator")
    }
  end

  describe ":open" do
    test "a POC opens a draft case", %{poc: poc} do
      case_record = Cases.open_case!(%{title: "SSH bug", description_md: "Bad."}, actor: poc)

      assert case_record.state == :draft
      assert case_record.title == "SSH bug"
      assert case_record.discovery == :unknown
    end

    test "a supporter opens a case too", %{supporter: supporter} do
      case_record = Cases.open_case!(%{title: "Supporter case"}, actor: supporter)

      assert case_record.state == :draft
    end

    test "a user with no role cannot open cases", %{collaborator: collaborator} do
      assert {:error, %Forbidden{}} =
               Cases.open_case(%{title: "nope"}, actor: collaborator)
    end

    test "whoever opens the case is assigned to it", %{poc: poc} do
      case_record = Cases.open_case!(%{title: "SSH bug"}, actor: poc)

      assert [assignment] = Ash.load!(case_record, [:assignments], actor: poc).assignments
      assert assignment.user_id == poc.id
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

    test "a user with no role sees only what they are assigned to", %{
      poc: poc,
      collaborator: collaborator
    } do
      assigned = Fixtures.open_case(poc, %{title: "assigned"})
      _other = Fixtures.open_case(poc, %{title: "other"})

      assert [] = Cases.list_cases!(actor: collaborator)

      Cases.assign_case_user!(%{case_id: assigned.id, user_id: collaborator.id}, actor: poc)

      assert [%{title: "assigned"}] = Cases.list_cases!(actor: collaborator)
    end
  end

  describe "what each role may do to a case it is assigned to" do
    setup %{poc: poc, supporter: supporter, collaborator: collaborator} do
      case_record = Fixtures.open_case(poc)

      for user <- [supporter, collaborator] do
        Cases.assign_case_user!(%{case_id: case_record.id, user_id: user.id}, actor: poc)
      end

      %{case_record: case_record}
    end

    test "an assigned supporter edits content", %{supporter: supporter, case_record: case_record} do
      assert %{description_md: "Edited."} =
               Cases.edit_case!(case_record, %{description_md: "Edited."}, actor: supporter)
    end

    test "an assigned user with no role may not edit", %{
      collaborator: collaborator,
      case_record: case_record
    } do
      assert {:error, %Forbidden{}} =
               Cases.edit_case(case_record, %{description_md: "Nope."}, actor: collaborator)
    end

    test "neither may approve or publish", %{
      supporter: supporter,
      collaborator: collaborator,
      case_record: case_record
    } do
      reviewed = Cases.request_case_review!(case_record, actor: supporter)

      for actor <- [supporter, collaborator] do
        assert {:error, %Forbidden{}} = Cases.approve_case(reviewed, actor: actor)
      end
    end

    test "an assigned supporter takes the next free CVE ID", %{
      supporter: supporter,
      case_record: case_record
    } do
      Fixtures.reserved_cve_record("CVE-2026-40001")

      assigned = Cases.assign_case_cve_id!(case_record, %{}, actor: supporter)

      assert Ash.load!(assigned, :cve_id, actor: supporter).cve_id == "CVE-2026-40001"
    end

    test "but may not name the ID they take", %{
      poc: poc,
      supporter: supporter,
      case_record: case_record
    } do
      reserved = Fixtures.reserved_cve_record("CVE-2026-40002")

      assert {:error, %Forbidden{}} =
               Cases.assign_case_cve_id(case_record, %{cve_record_id: reserved.id}, actor: supporter)

      # Refused outright rather than quietly given a different ID, and the
      # record they named stays in the pool.
      assert Varsel.CVE.get_cve_record!(reserved.id, actor: poc).state == :reserved
      assert is_nil(Ash.reload!(case_record, actor: poc).cve_record_id)
    end

    test "a POC may name it", %{poc: poc, case_record: case_record} do
      reserved = Fixtures.reserved_cve_record("CVE-2026-40003")

      assigned =
        Cases.assign_case_cve_id!(case_record, %{cve_record_id: reserved.id}, actor: poc)

      assert Ash.load!(assigned, :cve_id, actor: poc).cve_id == "CVE-2026-40003"
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

      assert {:error, %Forbidden{}} = Cases.edit_case(case_record, %{title: "nope"}, actor: poc)
    end

    test "a stale snapshot cannot edit a case approved in the meantime", %{poc: poc} do
      case_record = Fixtures.open_case(poc)
      in_review = Cases.request_case_review!(case_record, actor: poc)
      Cases.approve_case!(in_review, actor: poc)

      assert {:error, %Forbidden{}} =
               Cases.edit_case(in_review, %{title: "changed after approval"}, actor: poc)

      reloaded = Cases.get_case!(case_record.id, actor: poc)
      assert reloaded.state == :approved
      refute reloaded.title == "changed after approval"
    end

    test "a stale snapshot is rejected even when the case is still editable", %{poc: poc} do
      case_record = Fixtures.open_case(poc)
      in_review = Cases.request_case_review!(case_record, actor: poc)
      Cases.request_case_changes!(in_review, actor: poc)

      assert {:error, %Invalid{errors: [%StaleRecord{}]}} =
               Cases.edit_case(in_review, %{title: "changed after moving back"}, actor: poc)
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

      assert {:error, %Forbidden{}} =
               Cases.edit_affected_package(package, %{vendor: "nope"}, actor: poc)

      assert {:error, %Forbidden{}} =
               Cases.add_case_reference(
                 %{case_id: case_record.id, url: "https://example.com/advisory"},
                 actor: poc
               )
    end
  end

  describe "lifecycle transitions" do
    test "a stale snapshot cannot re-run a transition", %{poc: poc} do
      in_draft = Fixtures.open_case(poc)
      Cases.request_case_review!(in_draft, actor: poc)

      assert {:error, %Invalid{errors: [%StaleRecord{}]}} =
               Cases.request_case_review(in_draft, actor: poc)
    end

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

    test "a stale snapshot cannot assign twice, and the failed pick rolls back", %{poc: poc} do
      year = Date.utc_today().year
      Fixtures.reserved_cve_record("CVE-#{year}-11114")
      record_b = Fixtures.reserved_cve_record("CVE-#{year}-11115")

      stale_case = Fixtures.open_case(poc)
      Cases.assign_case_cve_id!(stale_case, %{}, actor: poc)

      assert {:error, %Invalid{errors: errors}} =
               Cases.assign_case_cve_id(stale_case, %{}, actor: poc)

      assert Enum.any?(errors, &match?(%StaleRecord{}, &1))

      # The before_action had already taken record B out of the pool; the
      # failed case update must roll that reservation transition back with it.
      assert Ash.get!(CveRecord, record_b.id, authorize?: false).state == :reserved
    end

    test "refuses a record another case already took", %{poc: poc} do
      year = Date.utc_today().year
      record = Fixtures.reserved_cve_record("CVE-#{year}-11116")

      case1 = Fixtures.open_case(poc)
      Cases.assign_case_cve_id!(case1, %{cve_record_id: record.id}, actor: poc)

      case2 = Fixtures.open_case(poc)

      assert {:error, error} =
               Cases.assign_case_cve_id(case2, %{cve_record_id: record.id}, actor: poc)

      assert Exception.message(error) =~ "CVE record is draft, not reserved"
      assert Ash.get!(Cases.Case, case2.id, authorize?: false).cve_record_id == nil
    end

    test "never auto-picks a withheld ID", %{poc: poc} do
      year = Date.utc_today().year
      withheld = Fixtures.reserved_cve_record("CVE-#{year}-11119")

      Ash.update!(withheld, %{withhold_reason: "held by the old system"},
        action: :withhold,
        authorize?: false
      )

      free = Fixtures.reserved_cve_record("CVE-#{year}-11120")

      case_record = Fixtures.open_case(poc)
      case_record = Cases.assign_case_cve_id!(case_record, %{}, actor: poc)

      # The withheld ID sorts lower, so it would have won the pick if the
      # pool query offered it at all.
      assert case_record.cve_record_id == free.id
      assert Ash.get!(CveRecord, withheld.id, authorize?: false).state == :withheld
    end

    test "assigns a withheld ID when it is named explicitly", %{poc: poc} do
      year = Date.utc_today().year
      record = Fixtures.reserved_cve_record("CVE-#{year}-11121")

      Ash.update!(record, %{withhold_reason: "held by the old system"},
        action: :withhold,
        authorize?: false
      )

      case_record = Fixtures.open_case(poc)

      case_record =
        Cases.assign_case_cve_id!(case_record, %{cve_record_id: record.id}, actor: poc)

      assert case_record.cve_record_id == record.id
      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
    end

    test "two cases assigned in sequence get different IDs", %{poc: poc} do
      year = Date.utc_today().year
      Fixtures.reserved_cve_record("CVE-#{year}-11117")
      Fixtures.reserved_cve_record("CVE-#{year}-11118")

      case1 = Fixtures.open_case(poc)
      case1 = Cases.assign_case_cve_id!(case1, %{}, actor: poc)

      case2 = Fixtures.open_case(poc)
      case2 = Cases.assign_case_cve_id!(case2, %{}, actor: poc)

      assert case1.cve_record_id != case2.cve_record_id
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
        Cases.propose_title!(%{case_id: case_record.id, value: "Better title"}, actor: poc)

      Cases.close_case!(case_record, %{}, actor: poc)

      proposal = Ash.get!(Cases.Proposal, proposal.id, authorize?: false)
      assert proposal.state == :superseded
      assert proposal.resolution_note =~ "closed"
    end
  end
end
