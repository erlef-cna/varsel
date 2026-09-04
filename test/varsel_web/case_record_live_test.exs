# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseRecordLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.Fixtures

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  # Links the case to a record that MITRE already holds, so the case is an
  # amendment in progress.
  defp link_published_record(case_record, cve_record) do
    Varsel.Repo.query!(
      "UPDATE cases SET cve_record_id = $1 WHERE id = $2",
      [Ecto.UUID.dump!(cve_record.id), Ecto.UUID.dump!(case_record.id)]
    )
  end

  setup %{conn: conn} do
    poc = Fixtures.register_user("case_record_poc", :poc)
    %{conn: conn, poc: poc}
  end

  describe "tabs" do
    test "every tab links to the others and marks its own", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Tabbed case"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      for {path, label} <- [{"cve", "CVE"}, {"osv", "OSV"}, {"publication", "Publication"}] do
        assert has_element?(lv, ~s(a[href="/cases/#{case_record.id}/#{path}"]), label)
      end

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/cve")

      assert has_element?(lv, ~s(a[href="/cases/#{case_record.id}"]), "Workspace")

      assert lv |> element(~s(a[href="/cases/#{case_record.id}/cve"] span)) |> render() =~
               "font-bold"
    end

    test "a case the actor cannot read sends them to the case list", %{conn: conn} do
      poc = Fixtures.register_user("case_record_other_poc", :poc)
      case_record = Fixtures.open_case(poc)
      stranger = Fixtures.register_user("case_record_stranger", :supporter)

      assert {:error, {:live_redirect, %{to: "/cases"}}} =
               conn |> log_in(stranger) |> live(~p"/cases/#{case_record.id}/cve")
    end

    test "lifecycle actions work from a record tab", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/osv")

      lv |> element("button", "Request review") |> render_click()
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :review

      assert render(lv) =~ "Approve"
    end

    test "publish lives on the Publication tab only", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Gated case", description_md: "desc"})
      case_record = Cases.request_case_review!(case_record, actor: poc)
      Cases.approve_case!(case_record, actor: poc)

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      refute html =~ ~s(phx-value-action="publish")
      refute render_async(lv) =~ ~s(phx-value-action="publish")

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/cve")
      refute render_async(lv) =~ ~s(phx-value-action="publish")

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/publication")
      html = render_async(lv)

      assert html =~ ~s(phx-value-action="publish")
      assert html =~ "opacity-45"
      assert html =~ "blocking publish"
    end
  end

  describe "Publication tab" do
    test "validation renders per-check rows with blocker deep links, not an alert box", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "Preview case", description_md: "desc"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/publication")
      html = render_async(lv)

      # Findings are ✗ rows, not an alert/callout box.
      refute html =~ "alert-warning"
      assert html =~ "✗"

      # EEF policy findings get per-section deep links into the workspace.
      assert html =~ "CVSS v4 vector is missing"
      assert has_element?(lv, ~s(a[href="/cases/#{case_record.id}#severity"]), "Go to severity")

      # Known validator findings link to the section that fixes them: the
      # missing-references cvelint error deep-links to the references section.
      assert has_element?(
               lv,
               ~s(a[href="/cases/#{case_record.id}#references"]),
               "Go to references"
             )

      # Validation runs against a placeholder CVE ID (no assignment needed), so
      # the per-check rows render.
      assert html =~ "cvelint"
      assert html =~ "CVE record schema"
      assert html =~ "Hex packages exist"
    end

    test "re-render renders the record again", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Stale case", description_md: "desc"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/publication")
      render_async(lv)

      Cases.edit_case!(case_record, %{title: "Fresh case"}, actor: poc)

      lv |> element("button", "Re-render") |> render_click()
      html = render_async(lv)

      assert html =~ "Fresh case"
    end
  end

  describe "CVE tab" do
    test "shows the open, syntax-tinted CNA container", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "JSON case", description_md: "desc"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/cve")
      html = render_async(lv)

      # The JSON is open (no <details>), Lumis-highlighted: keys are
      # .l-property tokens, string values .l-string.
      refute html =~ "CNA container JSON"
      assert html =~ ~s(<span class="l-property">&quot;descriptions&quot;</span>)
      assert html =~ ~s(<span class="l-string">)
    end

    test "amendments offer a diff against the published container", %{conn: conn, poc: poc} do
      year = Date.utc_today().year
      cve_record = Fixtures.published_cve_record("CVE-#{year}-55555", "Old title")
      case_record = Fixtures.open_case(poc, %{title: "New title"})
      link_published_record(case_record, cve_record)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/cve")
      assert render_async(lv) =~ "Diff to published"

      lv |> element("button", "Diff to published") |> render_click()
      html = render_async(lv)

      # The published title leaves, the case title arrives, tinted by the
      # Lumis diff grammar's minus/plus tokens.
      assert html =~ "Old title"
      assert html =~ "New title"
      assert html =~ ~s(<span class="l-diff-minus">)
      assert html =~ ~s(<span class="l-diff-plus">)
    end

    test "never-published cases show no diff button", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/cve")

      refute render_async(lv) =~ "Diff to published"
    end
  end

  describe "OSV tab" do
    test "says why a record without packages has no OSV document", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "OSV case", description_md: "desc"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/osv")

      assert render_async(lv) =~ "No OSV record: No hex, npm, or git repositories"
    end

    test "diffs against the published OSV record", %{conn: conn, poc: poc} do
      year = Date.utc_today().year
      cve_record = Fixtures.published_cve_record("CVE-#{year}-55556", "Old title")

      now = DateTime.utc_now()

      Ash.create!(
        Varsel.CVE.OsvRecord,
        %{
          osv_id: "EEF-CVE-#{year}-55556",
          cve_record_id: cve_record.id,
          osv_json: %{"id" => "EEF-CVE-#{year}-55556", "summary" => "Old summary"},
          content_hash: "old",
          modified_at: now,
          synced_at: now
        },
        action: :create,
        authorize?: false
      )

      case_record = Fixtures.open_case(poc, %{title: "New title"})
      link_published_record(case_record, cve_record)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/osv")
      render_async(lv)

      lv |> element(~s(button[phx-value-view="diff"])) |> render_click()
      html = render_async(lv)

      # The case has no packages, so the preview derives no OSV document: the
      # published one leaves in full.
      assert html =~ "Old summary"
      assert html =~ ~s(<span class="l-diff-minus">)
    end
  end
end
