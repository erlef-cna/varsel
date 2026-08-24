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
  alias Varsel.Notifications

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

  # Each decision is taken in its own box, opened from the row it belongs to.
  defp decide(lv, report, decision) do
    lv
    |> element("button[phx-value-decision=#{decision}][phx-value-report_id='#{report.id}']")
    |> render_click()

    element(lv, "#decision-form-#{report.id}")
  end

  setup %{conn: conn} do
    poc = Fixtures.register_user("triage_live_poc", :poc)
    reporter = Fixtures.register_user("triage_live_reporter")

    %{conn: conn, poc: poc, reporter: reporter}
  end

  test "requires a signed-in user", %{conn: conn} do
    assert_raise Ash.Error.Forbidden, fn -> live(conn, ~p"/reports") end
  end

  describe "reporter view" do
    test "shows only the reporter's own reports, without triage tooling", %{
      conn: conn,
      poc: poc,
      reporter: reporter
    } do
      submit_report(reporter, "my own report")
      other = Fixtures.register_user("triage_live_bystander")
      submit_report(other, "somebody else's report")
      # POC-submitted reports are equally invisible to a plain reporter.
      submit_report(poc, "a poc report")

      {:ok, lv, html} = conn |> log_in(reporter) |> live(~p"/reports")

      assert has_element?(lv, "h3", "my own report")
      refute has_element?(lv, "h3", "somebody else's report")
      refute has_element?(lv, "h3", "a poc report")

      assert html =~ "My Reports"
      assert html =~ "The CNA team triages every report"
      # The submit call-to-action stays; triage tooling does not.
      assert has_element?(lv, "a[href='/report']")
      refute has_element?(lv, "button[phx-value-filter]")
      refute has_element?(lv, "[phx-click=toggle_payload]")
    end

    test "withdrawing a submitted report rejects it and records the withdrawal", %{
      conn: conn,
      reporter: reporter
    } do
      report = submit_report(reporter, "never mind this one")

      {:ok, lv, _html} = conn |> log_in(reporter) |> live(~p"/reports")

      lv |> element("button[phx-value-report_id='#{report.id}']") |> render_click()

      report = Ash.get!(CVE.VulnerabilityReport, report.id, authorize?: false)
      assert report.state == :rejected
      assert report.triage_notes =~ "Withdrawn by the reporter"

      refute has_element?(lv, "button[phx-value-report_id='#{report.id}']")
    end

    test "a report already under triage can no longer be withdrawn", %{
      conn: conn,
      poc: poc,
      reporter: reporter
    } do
      report = submit_report(reporter, "already being looked at")
      CVE.triage_vulnerability_report!(report, %{}, actor: poc)

      {:ok, lv, _html} = conn |> log_in(reporter) |> live(~p"/reports")

      assert has_element?(lv, "h3", "already being looked at")
      refute has_element?(lv, "button[phx-value-report_id='#{report.id}']")
    end
  end

  test "resolved reports leave the default queue but stay reachable", %{
    conn: conn,
    poc: poc,
    reporter: reporter
  } do
    submit_report(reporter, "Waiting report")
    accepted = submit_report(reporter, "Consolidated report")
    CVE.accept_vulnerability_report!(accepted, %{}, actor: poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/reports")

    # The accepted report's case title shows up in the accept-into-case
    # select, so assert on the card headings.
    assert has_element?(lv, "h3", "Waiting report")
    refute has_element?(lv, "h3", "Consolidated report")

    # The stat tiles and the scope tabs both select a scope; drive the tiles.
    lv |> element("button.rounded-lg[phx-value-filter=accepted]") |> render_click()
    assert has_element?(lv, "h3", "Consolidated report")
    refute has_element?(lv, "h3", "Waiting report")

    lv |> element("button.rounded-lg[phx-value-filter=all]") |> render_click()
    assert has_element?(lv, "h3", "Consolidated report")
    assert has_element?(lv, "h3", "Waiting report")
  end

  # A payload with no `report` body is all the report says, so it needs no
  # disclosure to sit behind — it renders open.
  test "lists reports with their payload", %{conn: conn, poc: poc, reporter: reporter} do
    submit_report(reporter, "acme_lib leaks secrets")

    {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/reports")

    assert has_element?(lv, "h3", "acme_lib leaks secrets")
    assert html =~ "triage_live_reporter"

    refute has_element?(lv, "[phx-click=toggle_payload]")
    assert lv |> element("pre") |> render() =~ "leaks secrets"
  end

  test "a markdown body reads as prose, with the rest behind a disclosure", %{
    conn: conn,
    poc: poc,
    reporter: reporter
  } do
    CVE.submit_vulnerability_report!(
      %{
        report_json: %{
          "report" => "## Heap overflow\n\nThe parser never bounds the length.",
          "affected" => "acme_lib"
        },
        summary: "acme_lib overflows",
        confirms_criteria: true,
        confirms_in_scope: true
      },
      actor: reporter
    )

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/reports")

    assert lv |> element(".prose h2") |> render() =~ "Heap overflow"

    # The leftovers start closed and open on demand.
    refute has_element?(lv, "pre")
    lv |> element("[phx-click=toggle_payload]") |> render_click()
    assert lv |> element("pre") |> render() =~ "acme_lib"
  end

  test "accepting without a case opens a draft case and navigates to it", %{
    conn: conn,
    poc: poc,
    reporter: reporter
  } do
    report = submit_report(reporter, "acme_lib leaks secrets")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/reports")

    lv
    |> decide(report, :accept)
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
    |> decide(report, :accept)
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
    |> decide(report, :triage)
    |> render_submit(%{"triage_notes" => "checking upstream"})

    report = Ash.get!(CVE.VulnerabilityReport, report.id, authorize?: false)
    assert report.state == :triaged
    assert report.triage_notes == "checking upstream"

    lv
    |> decide(report, :reject)
    |> render_submit(%{"triage_notes" => "out of scope"})

    report = Ash.get!(CVE.VulnerabilityReport, report.id, authorize?: false)
    assert report.state == :rejected
    assert report.triage_notes == "out of scope"
  end

  describe "the people a sender named" do
    setup do
      report =
        CVE.submit_hex_vulnerability_report!(
          %{
            report_json: %{"package" => "acme"},
            summary: "forwarded by hex.pm",
            participants: [
              %{
                role: :reporter,
                strategy: :hex,
                username: "triage_reporter",
                email: "reporter@example.com"
              },
              %{
                role: :maintainer,
                strategy: :hex,
                username: "triage_maintainer",
                email: "maintainer@example.com"
              }
            ]
          },
          authorize?: false
        )

      %{hex_report: report}
    end

    test "a reporter who has not signed in yet is not shown as deleted", %{conn: conn, poc: poc} do
      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/reports")

      assert html =~ "forwarded by hex.pm"
      refute html =~ "Deleted user"
    end

    test "a reporter whose account went away still is", %{
      conn: conn,
      poc: poc,
      hex_report: report
    } do
      report
      |> Ash.load!([:participants], authorize?: false)
      |> Map.fetch!(:participants)
      |> Enum.each(&Ash.destroy!(&1, action: :spend, authorize?: false))

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/reports")

      assert html =~ "Deleted user"
    end

    test "are listed for a POC", %{conn: conn, poc: poc} do
      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/reports")

      assert html =~ "Named by the sender"
      assert html =~ "triage_maintainer"
      assert html =~ "maintainer@example.com"
    end

    test "stay hidden from the reporter's own list", %{conn: conn, hex_report: report} do
      reporter = Fixtures.register_user("triage_reporter_view")
      Ash.Seed.update!(report, %{reporter_id: reporter.id})

      {:ok, _lv, html} = conn |> log_in(reporter) |> live(~p"/reports")

      assert html =~ "forwarded by hex.pm"
      refute html =~ "Named by the sender"
      refute html =~ "triage_maintainer"
      refute html =~ "maintainer@example.com"
    end
  end

  describe "notification auto-read" do
    test "a POC visiting the triage queue marks their unread report_submitted notifications read",
         %{
           conn: conn,
           poc: poc,
           reporter: reporter
         } do
      report = submit_report(reporter, "auto-read on triage visit")

      Notifications.record_notification!(
        %{kind: :report_submitted, user_id: poc.id, vulnerability_report_id: report.id},
        authorize?: false
      )

      assert [_unread] = Notifications.list_unread_notifications!(actor: poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/reports")

      assert render(lv) =~ "auto-read on triage visit"
      assert Notifications.list_unread_notifications!(actor: poc) == []
    end

    test "a plain reporter's own visit does not touch anyone's notifications", %{
      conn: conn,
      poc: poc,
      reporter: reporter
    } do
      report = submit_report(reporter, "reporter visit stays inert")

      Notifications.record_notification!(
        %{kind: :report_submitted, user_id: poc.id, vulnerability_report_id: report.id},
        authorize?: false
      )

      {:ok, lv, _html} = conn |> log_in(reporter) |> live(~p"/reports")

      assert render(lv) =~ "My Reports"
      assert [_still_unread] = Notifications.list_unread_notifications!(actor: poc)
    end
  end
end
