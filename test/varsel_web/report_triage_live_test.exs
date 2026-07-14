# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ReportTriageLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.Fixtures

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  defp submit_report(reporter, summary) do
    CVE.submit_vulnerability_report!(
      %{
        report_json: %{"package" => "acme_lib", "details" => "leaks secrets"},
        summary: summary,
        confirms_criteria: true,
        confirms_in_scope: true
      },
      actor: reporter
    )
  end

  setup %{conn: conn} do
    poc = Fixtures.register_user("triage_live_poc", :poc)
    reporter = Fixtures.register_user("triage_live_reporter")

    %{conn: conn, poc: poc, reporter: reporter}
  end

  test "requires the POC role", %{conn: conn, reporter: reporter} do
    assert {:error, {:redirect, %{to: "/"}}} = conn |> log_in(reporter) |> live(~p"/reports")
  end

  test "lists reports with their payload", %{conn: conn, poc: poc, reporter: reporter} do
    submit_report(reporter, "acme_lib leaks secrets")

    {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/reports")

    assert html =~ "acme_lib leaks secrets"
    assert html =~ "triage_live_reporter"
    assert html =~ "leaks secrets"
  end

  test "accepting without a case opens a draft case and navigates to it", %{
    conn: conn,
    poc: poc,
    reporter: reporter
  } do
    report = submit_report(reporter, "acme_lib leaks secrets")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/reports")

    lv
    |> element("#accept-#{report.id}")
    |> render_submit(%{"case_id" => "", "triage_notes" => "looks real"})

    assert {path, _flash} = assert_redirect(lv)
    assert [_, case_id] = Regex.run(~r{^/cases/(.+)$}, path)

    case_record = Ash.get!(Cases.Case, case_id, authorize?: false)
    assert case_record.title == "acme_lib leaks secrets"
    assert case_record.state == :draft

    report = Ash.get!(CVE.VulnerabilityReport, report.id, authorize?: false)
    assert report.state == :accepted
    assert report.case_id == case_record.id
    assert report.triage_notes == "looks real"
  end

  test "accepting into an existing case consolidates", %{conn: conn, poc: poc, reporter: reporter} do
    report = submit_report(reporter, "another report")
    case_record = Fixtures.open_case(poc, %{title: "Existing case"})

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/reports")

    lv
    |> element("#accept-#{report.id}")
    |> render_submit(%{"case_id" => case_record.id})

    assert {path, _flash} = assert_redirect(lv)
    assert path == "/cases/#{case_record.id}"

    assert Ash.get!(CVE.VulnerabilityReport, report.id, authorize?: false).case_id ==
             case_record.id
  end

  test "triage and reject record notes", %{conn: conn, poc: poc, reporter: reporter} do
    report = submit_report(reporter, "needs a look")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/reports")

    lv
    |> element("#triage-#{report.id}")
    |> render_submit(%{"triage_notes" => "checking upstream"})

    report = Ash.get!(CVE.VulnerabilityReport, report.id, authorize?: false)
    assert report.state == :triaged
    assert report.triage_notes == "checking upstream"

    lv
    |> element("#reject-#{report.id}")
    |> render_submit(%{"triage_notes" => "out of scope"})

    report = Ash.get!(CVE.VulnerabilityReport, report.id, authorize?: false)
    assert report.state == :rejected
    assert report.triage_notes == "out of scope"
  end
end
