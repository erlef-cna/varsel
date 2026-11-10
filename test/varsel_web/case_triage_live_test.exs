# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseTriageLiveTest do
  use VarselWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.Fixtures

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  defp reload(case_record), do: Ash.get!(Cases.Case, case_record.id, authorize?: false)

  setup %{conn: conn} do
    poc = Fixtures.register_user("case_triage_poc", :poc)
    reporter = Fixtures.register_user("case_triage_reporter")

    case_record =
      Cases.submit_vulnerability_report!(
        %{
          report_json: %{"report" => "Bad."},
          summary: "acme leaks secrets",
          confirms_criteria: true,
          confirms_in_scope: true
        },
        actor: reporter
      )

    %{conn: conn, poc: poc, reporter: reporter, case: case_record}
  end

  describe "the board" do
    test "shows a POC the reported case in the submitted lane", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases")

      assert has_element?(lv, ~s(#lane-submitted a[href="/cases/#{case_record.id}"]))

      Cases.triage_case!(case_record, actor: poc)

      assert has_element?(lv, ~s(#lane-triage a[href="/cases/#{case_record.id}"]))
      refute has_element?(lv, ~s(#lane-submitted a[href="/cases/#{case_record.id}"]))
    end

    test "shows the reporter their own case and nobody else's", %{
      conn: conn,
      reporter: reporter,
      case: case_record
    } do
      other = Fixtures.register_user("case_triage_other")

      other_case =
        Cases.submit_vulnerability_report!(
          %{
            report_json: %{"report" => "Other."},
            summary: "someone else's",
            confirms_criteria: true,
            confirms_in_scope: true
          },
          actor: other
        )

      {:ok, lv, _html} = conn |> log_in(reporter) |> live(~p"/cases")

      assert has_element?(lv, ~s(#lane-submitted a[href="/cases/#{case_record.id}"]))
      refute has_element?(lv, ~s(a[href="/cases/#{other_case.id}"]))
    end
  end

  test "a POC accepts the case", %{conn: conn, poc: poc, case: case_record} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

    lv |> element("button[phx-value-action=accept]") |> render_click()

    assert %{state: :draft, accepted_at: %DateTime{}} = reload(case_record)
    refute has_element?(lv, "button[phx-value-action=accept]")
  end

  test "a POC moves the case under triage", %{conn: conn, poc: poc, case: case_record} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

    lv |> element("button[phx-value-action=triage]") |> render_click()

    assert reload(case_record).state == :triage
    refute has_element?(lv, "button[phx-value-action=triage]")
  end

  test "a POC rejects the case with a reason", %{conn: conn, poc: poc, case: case_record} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

    lv |> element("button[phx-value-modal=reject]") |> render_click()
    lv |> form("#reject-case-form", %{"closed_reason" => "Out of scope."}) |> render_submit()

    assert %{state: :closed, closed_reason: "Out of scope."} = reload(case_record)
    refute has_element?(lv, "#reject-case-modal")
    refute has_element?(lv, "button[phx-value-modal=reject]")
  end

  # The comments tab has no triage panel of its own: the header carries the
  # same actions as on the workspace.
  test "a POC rejects the case from any tab", %{conn: conn, poc: poc, case: case_record} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")

    lv |> element("button[phx-value-modal=reject]") |> render_click()
    lv |> form("#reject-case-form", %{"closed_reason" => "Duplicate."}) |> render_submit()

    assert %{state: :closed, closed_reason: "Duplicate."} = reload(case_record)
    refute has_element?(lv, "#reject-case-modal")
  end

  test "cancelling a lifecycle modal changes nothing", %{conn: conn, poc: poc, case: case_record} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

    lv |> element("button[phx-value-modal=reject]") |> render_click()
    assert has_element?(lv, "#reject-case-modal")

    lv |> element("#reject-case-modal button", "Cancel") |> render_click()

    refute has_element?(lv, "#reject-case-modal")
    assert reload(case_record).state == :submitted
  end

  test "an assigned supporter drafts the case but cannot close it", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    supporter = Fixtures.register_user("case_triage_supporter", :supporter)
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
    Cases.accept_case!(case_record, actor: poc)

    {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}")

    assert has_element?(lv, "button[phx-value-action=request_review]")
    refute has_element?(lv, "button[phx-value-modal=close]")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

    assert has_element?(lv, "button[phx-value-modal=close]")
  end

  test "a POC splits off a finding into a new case", %{conn: conn, poc: poc, case: case_record} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

    lv |> element("button[phx-value-modal=split]") |> render_click()
    lv |> form("#split-case-form", %{"title" => "acme also crashes"}) |> render_submit()

    {path, _flash} = assert_redirect(lv)
    assert [_, split_id] = Regex.run(~r{^/cases/(.+)$}, path)
    assert split_id != case_record.id

    assert %{title: "acme also crashes", state: :triage} =
             Ash.get!(Cases.Case, split_id, authorize?: false)
  end

  test "a POC merges the case into another", %{conn: conn, poc: poc, case: case_record} do
    target = Fixtures.open_case(poc, %{title: "Same finding"})

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

    other = Fixtures.open_case(poc, %{title: "Unrelated finding"})

    lv |> element("button[phx-value-modal=merge]") |> render_click()
    lv |> form("#merge-case-form", %{"query" => "same"}) |> render_change()

    assert has_element?(lv, ~s(#merge-target-picker input[value="#{target.id}"]))
    refute has_element?(lv, ~s(#merge-target-picker input[value="#{other.id}"]))
    refute has_element?(lv, ~s(#merge-target-picker input[value="#{case_record.id}"]))

    lv |> form("#merge-case-form", %{"into_case_id" => target.id}) |> render_submit()

    assert_redirect(lv, ~p"/cases/#{target.id}")
    assert %{state: :merged, merged_into_id: merged_into_id} = reload(case_record)
    assert merged_into_id == target.id
  end

  test "the reporter withdraws, and decides nothing else", %{
    conn: conn,
    reporter: reporter,
    case: case_record
  } do
    {:ok, lv, _html} = conn |> log_in(reporter) |> live(~p"/cases/#{case_record.id}")

    refute has_element?(lv, "button[phx-value-action=accept]")
    refute has_element?(lv, "button[phx-click=open_lifecycle_modal]")

    lv |> element("button[phx-value-action=withdraw]") |> render_click()

    assert reload(case_record).state == :closed
    refute has_element?(lv, "button[phx-value-action=withdraw]")
  end
end
