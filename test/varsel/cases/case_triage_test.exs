# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseTriageTest do
  use Varsel.DataCase, async: true

  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseInvite
  alias Varsel.Cases.VulnerabilityReport
  alias Varsel.Fixtures
  alias Varsel.HexPm
  alias Varsel.Service

  require Ash.Query

  setup do
    Req.Test.stub(HexPm, fn conn ->
      case conn.path_info do
        ["api", "users", "triage_" <> _rest = username, "contact"] ->
          Req.Test.json(conn, %{
            "username" => username,
            "name" => username,
            "email" => "#{username}@example.com"
          })

        _unknown ->
          Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    poc = Fixtures.register_user("triage_poc", :poc)
    reporter = Fixtures.register_user("triage_web_reporter")

    case_record =
      Cases.submit_vulnerability_report!(
        %{
          report_json: %{"report" => "Bad."},
          summary: "acme leaks secrets",
          confirms_criteria: true,
          confirms_in_scope: true
        },
        actor: reporter,
        load: [:vulnerability_reports]
      )

    [report] = case_record.vulnerability_reports

    %{poc: poc, reporter: reporter, report: report, case: case_record}
  end

  # The report, with the cases it led to.
  defp submit_from_hex(maintainers) do
    %{vulnerability_reports: [report]} =
      Cases.submit_hex_vulnerability_report!(
        %{
          report_json: %{"report" => "Bad.", "package" => "acme"},
          summary: "acme leaks secrets",
          reporter_username: "triage_hex_reporter",
          reporter_email: "triage_hex_reporter@example.com",
          maintainers: maintainers
        },
        actor: Service.hexpm_intake()
      )

    Ash.load!(report, :cases, authorize?: false)
  end

  defp invites(case_id) do
    CaseInvite
    |> Ash.Query.filter(case_id == ^case_id)
    |> Ash.read!(authorize?: false)
  end

  describe "a submitted report" do
    test "opens a case in :submitted that cites it and is not accepted", %{
      case: case_record,
      report: report,
      reporter: reporter
    } do
      case_record =
        Ash.load!(case_record, [:vulnerability_reports, :assignments], authorize?: false)

      assert case_record.state == :submitted
      assert case_record.title == "acme leaks secrets"
      assert is_nil(case_record.accepted_at)
      assert [%{id: report_id}] = case_record.vulnerability_reports
      assert report_id == report.id
      assert [%{user_id: user_id}] = case_record.assignments
      assert user_id == reporter.id
    end

    test "a POC edits its content, the reporter only proposes", %{
      poc: poc,
      reporter: reporter,
      case: case_record
    } do
      assert {:error, _error} = Cases.edit_case(case_record, %{title: "Mine"}, actor: reporter)

      edited = Cases.edit_case!(case_record, %{title: "Better", description_md: "x"}, actor: poc)
      assert %{title: "Better", description_md: "x"} = edited
    end

    test "under triage its content stays editable", %{poc: poc, case: case_record} do
      triaged = Cases.triage_case!(case_record, actor: poc)

      assert %{title: "Better"} = Cases.edit_case!(triaged, %{title: "Better"}, actor: poc)
    end
  end

  describe "deciding" do
    test "a POC moves it under triage and accepts it", %{poc: poc, case: case_record} do
      triaged = Cases.triage_case!(case_record, actor: poc)
      assert triaged.state == :triage

      accepted = Cases.accept_case!(triaged, actor: poc)
      assert accepted.state == :draft
      assert %DateTime{} = accepted.accepted_at
    end

    test "nobody else decides", %{reporter: reporter, case: case_record} do
      supporter = Fixtures.register_user("triage_supporter", :supporter)

      for actor <- [reporter, supporter] do
        assert {:error, _error} = Cases.triage_case(case_record, actor: actor)
        assert {:error, _error} = Cases.accept_case(case_record, actor: actor)
        assert {:error, _error} = Cases.reject_case(case_record, %{}, actor: actor)
      end
    end

    test "a supporter assigned to the case decides", %{poc: poc, case: case_record} do
      supporter = Fixtures.register_user("triage_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      edited = Cases.edit_case!(case_record, %{title: "Better"}, actor: supporter)
      triaged = Cases.triage_case!(edited, actor: supporter)
      assert %{state: :draft} = Cases.accept_case!(triaged, actor: supporter)
    end

    test "a supporter assigned to the case rejects it", %{poc: poc, case: case_record} do
      supporter = Fixtures.register_user("triage_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      assert %{state: :closed} = Cases.reject_case!(case_record, %{}, actor: supporter)
    end

    test "a POC rejects it with a reason", %{poc: poc, case: case_record} do
      rejected = Cases.reject_case!(case_record, %{closed_reason: "Out of scope."}, actor: poc)

      assert rejected.state == :closed
      assert rejected.closed_reason == "Out of scope."
      assert is_nil(rejected.accepted_at)
    end

    test "a stale snapshot cannot decide a case decided in the meantime", %{
      poc: poc,
      case: case_record
    } do
      Cases.reject_case!(case_record, %{}, actor: poc)

      assert {:error, %Invalid{errors: [%Ash.Error.Changes.StaleRecord{}]}} =
               Cases.accept_case(case_record, actor: poc)
    end
  end

  describe ":withdraw" do
    test "the reporter withdraws their case before acceptance", %{
      reporter: reporter,
      case: case_record
    } do
      withdrawn = Cases.withdraw_case!(case_record, actor: reporter)

      assert withdrawn.state == :closed
      assert withdrawn.closed_reason == "Withdrawn by the reporter."
    end

    test "under triage it still may", %{poc: poc, reporter: reporter, case: case_record} do
      triaged = Cases.triage_case!(case_record, actor: poc)

      assert {:ok, _withdrawn} = Cases.withdraw_case(triaged, actor: reporter)
    end

    test "nobody but the reporter withdraws", %{poc: poc, case: case_record} do
      bystander = Fixtures.register_user("triage_bystander")

      assert {:error, _error} = Cases.withdraw_case(case_record, actor: poc)
      assert {:error, _error} = Cases.withdraw_case(case_record, actor: bystander)
    end

    test "an accepted case can no longer be withdrawn", %{
      poc: poc,
      reporter: reporter,
      case: case_record
    } do
      accepted = Cases.accept_case!(case_record, actor: poc)

      assert {:error, _error} = Cases.withdraw_case(accepted, actor: reporter)
    end
  end

  describe "a report hex.pm forwarded" do
    test "invites the reporter and the maintainers at once" do
      known = Fixtures.sign_in_with_hex("triage_known", 7001)

      report =
        submit_from_hex([
          %{username: "triage_known", email: "triage_known@example.com"},
          %{username: "triage_stranger", email: "triage_stranger@example.com"}
        ])

      [case_record] = report.cases
      case_record = Ash.load!(case_record, [:assignments], authorize?: false)

      assert MapSet.new(case_record.assignments, & &1.user_id) == MapSet.new([known.id])

      assert case_record.id |> invites() |> MapSet.new(&to_string(&1.username)) ==
               MapSet.new(["triage_hex_reporter", "triage_stranger"])
    end

    test "invites the maintainers as maintainers and the reporter as someone else" do
      [case_record] =
        submit_from_hex([
          %{username: "triage_role_maintainer", email: "triage_role_maintainer@example.com"}
        ]).cases

      roles = Map.new(invites(case_record.id), &{to_string(&1.username), &1.role})

      assert roles == %{"triage_hex_reporter" => :other, "triage_role_maintainer" => :maintainer}
    end

    test "names someone who reports a package they maintain once" do
      report =
        submit_from_hex([
          %{username: "triage_hex_reporter", email: "triage_hex_reporter@example.com"}
        ])

      [case_record] = report.cases

      assert [_one] = invites(case_record.id)
    end

    test "fails as a whole when a named person cannot be invited" do
      assert_raise Invalid, fn -> submit_from_hex([%{username: "nobody_at_hex", email: nil}]) end

      assert [] =
               VulnerabilityReport
               |> Ash.Query.filter(source == :hex)
               |> Ash.read!(authorize?: false)
    end

    test "rejecting withdraws the open invites", %{poc: poc} do
      [case_record] = submit_from_hex([%{username: "triage_stranger", email: nil}]).cases

      Cases.reject_case!(case_record, %{}, actor: poc)

      assert [] = invites(case_record.id)
    end

    test "closing an accepted case keeps its invites", %{poc: poc} do
      [case_record] = submit_from_hex([%{username: "triage_stranger", email: nil}]).cases

      case_record
      |> Cases.accept_case!(actor: poc)
      |> Cases.close_case!(%{}, actor: poc)

      assert [_reporter, _stranger] = invites(case_record.id)
    end

    test "the reporter's withdrawal withdraws the open invites" do
      [case_record] = submit_from_hex([%{username: "triage_stranger", email: nil}]).cases
      reporter = Fixtures.sign_in_with_hex("triage_hex_reporter", 7002)

      # Signing in claimed the reporter's own invite and the report.
      assert [%{username: username}] = invites(case_record.id)
      assert to_string(username) == "triage_stranger"

      case_record = Ash.reload!(case_record, authorize?: false)
      Cases.withdraw_case!(case_record, actor: reporter)

      assert [] = invites(case_record.id)
    end
  end

  describe "the people on a reported case" do
    setup %{poc: poc} do
      maintainer = Fixtures.sign_in_with_hex("triage_known", 7101)
      reporter = Fixtures.sign_in_with_hex("triage_hex_reporter", 7102)

      report =
        submit_from_hex([
          %{username: "triage_known", email: nil},
          %{username: "triage_stranger", email: nil}
        ])

      [case_record] = report.cases

      %{poc: poc, maintainer: maintainer, hex_reporter: reporter, hex_case: case_record}
    end

    test "see each other and who reported, but no invite address", %{
      maintainer: maintainer,
      hex_reporter: reporter,
      hex_case: case_record
    } do
      loaded =
        Cases.get_case!(case_record.id,
          actor: maintainer,
          load: [:assignments, :invites, vulnerability_reports: [:reporter_username, :reporter]]
        )

      assert MapSet.new(loaded.assignments, & &1.user_id) ==
               MapSet.new([maintainer.id, reporter.id])

      assert [%{email: %Ash.ForbiddenField{}}] = loaded.invites
      assert [report] = loaded.vulnerability_reports
      assert to_string(report.reporter_username) == "triage_hex_reporter"
      assert report.reporter.id == reporter.id
    end

    test "a POC reads the invite address", %{poc: poc, hex_case: case_record} do
      loaded = Cases.get_case!(case_record.id, actor: poc, load: [:invites])

      assert [%{email: email}] = loaded.invites
      assert to_string(email) == "triage_stranger@example.com"
    end

    test "a supporter not on the case sees nothing of it", %{hex_case: case_record} do
      supporter = Fixtures.register_user("triage_supporter", :supporter)

      assert {:error, _error} = Cases.get_case(case_record.id, actor: supporter)
    end
  end

  describe ":merge" do
    test "the takeover runs only through the merge", %{poc: poc, case: case_record} do
      target = Fixtures.open_case(poc, %{title: "Same finding"})

      assert {:error, %Ash.Error.Forbidden{}} =
               target
               |> Ash.Changeset.for_update(:absorb_merged, %{source_case_id: case_record.id}, actor: poc)
               |> Ash.update()
    end

    test "an assigned supporter merges into a case they also work", %{
      poc: poc,
      reporter: reporter,
      case: case_record
    } do
      supporter = Fixtures.register_user("triage_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      elsewhere = Fixtures.open_case(poc, %{title: "Not theirs"})

      assert {:error, _error} = Cases.merge_case(case_record, elsewhere.id, actor: supporter)

      target = Fixtures.open_case(poc, %{title: "Same finding"})
      Cases.assign_case_user!(%{case_id: target.id, user_id: supporter.id}, actor: poc)

      case_record = Ash.reload!(case_record, authorize?: false)
      assert %{state: :merged} = Cases.merge_case!(case_record, target.id, actor: supporter)

      target = Ash.load!(target, [:vulnerability_reports, :assignments], authorize?: false)
      assert [_report] = target.vulnerability_reports
      assert reporter.id in Enum.map(target.assignments, & &1.user_id)
    end

    test "the target cites the reports and takes the people", %{
      poc: poc,
      reporter: reporter,
      report: report,
      case: case_record
    } do
      target = Fixtures.open_case(poc, %{title: "Same finding"})

      merged = Cases.merge_case!(case_record, target.id, actor: poc)

      assert merged.state == :merged
      assert merged.merged_into_id == target.id

      target = Ash.load!(target, [:vulnerability_reports, :assignments], authorize?: false)
      assert [%{id: report_id}] = target.vulnerability_reports
      assert report_id == report.id
      assert reporter.id in Enum.map(target.assignments, & &1.user_id)

      # The source keeps its citation too.
      report = Ash.load!(report, [:cases], authorize?: false)
      assert MapSet.new(report.cases, & &1.id) == MapSet.new([merged.id, target.id])
    end

    test "re-invites the source's people on the target and withdraws the source's invites", %{
      poc: poc
    } do
      [case_record] = submit_from_hex([%{username: "triage_stranger", email: nil}]).cases
      target = Fixtures.open_case(poc, %{title: "Same finding"})

      Cases.merge_case!(case_record, target.id, actor: poc)

      assert [] = invites(case_record.id)

      assert target.id |> invites() |> MapSet.new(&to_string(&1.username)) ==
               MapSet.new(["triage_hex_reporter", "triage_stranger"])
    end

    test "refuses the case itself and a closed target", %{poc: poc, case: case_record} do
      assert {:error, _error} = Cases.merge_case(case_record, case_record.id, actor: poc)

      closed = Fixtures.open_case(poc)
      Cases.close_case!(closed, %{}, actor: poc)

      assert {:error, _error} = Cases.merge_case(case_record, closed.id, actor: poc)
    end
  end

  describe ":split" do
    test "opens a case under triage that cites the same reports and people", %{
      poc: poc,
      reporter: reporter,
      report: report,
      case: case_record
    } do
      split = Cases.split_case!(case_record.id, %{title: "Second finding"}, actor: poc)

      split = Ash.load!(split, [:vulnerability_reports, :assignments], authorize?: false)
      assert split.state == :triage
      assert is_nil(split.accepted_at)
      assert [%{id: report_id}] = split.vulnerability_reports
      assert report_id == report.id
      assert reporter.id in Enum.map(split.assignments, & &1.user_id)
    end

    test "a POC or an assigned supporter splits, nobody else", %{
      poc: poc,
      reporter: reporter,
      case: case_record
    } do
      supporter = Fixtures.register_user("triage_supporter", :supporter)

      assert {:error, _error} = Cases.split_case(case_record.id, %{title: "x"}, actor: reporter)
      assert {:error, _error} = Cases.split_case(case_record.id, %{title: "x"}, actor: supporter)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      split = Cases.split_case!(case_record.id, %{title: "Second finding"}, actor: supporter)

      split = Ash.load!(split, [:vulnerability_reports, :assignments], authorize?: false)
      assert [_report] = split.vulnerability_reports

      assert MapSet.new(split.assignments, & &1.user_id) ==
               MapSet.new([reporter.id, supporter.id])
    end
  end

  test "a case opened directly is accepted from the start", %{poc: poc} do
    assert %Case{accepted_at: %DateTime{}} = Fixtures.open_case(poc)
  end
end
