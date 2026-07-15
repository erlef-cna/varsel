# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseLiveTest do
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

  setup %{conn: conn} do
    poc = Fixtures.register_user("case_live_poc", :poc)
    supporter = Fixtures.register_user("case_live_supporter", :supporter)

    %{conn: conn, poc: poc, supporter: supporter}
  end

  describe "case list" do
    test "requires login", %{conn: conn} do
      assert {:error, {:redirect, %{to: "/sign-in"}}} = live(conn, ~p"/cases")
    end

    test "a POC sees all cases and can open one", %{conn: conn, poc: poc} do
      Fixtures.open_case(poc, %{title: "Existing case"})

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases")
      assert html =~ "Existing case"

      lv
      |> form("form[phx-submit=open_case]", %{"title" => "Fresh case"})
      |> render_submit()

      assert {path, _flash} = assert_redirect(lv)
      assert path =~ ~r{^/cases/}
    end

    test "a supporter only sees assigned cases", %{conn: conn, poc: poc, supporter: supporter} do
      assigned = Fixtures.open_case(poc, %{title: "Assigned case"})
      Fixtures.open_case(poc, %{title: "Hidden case"})
      Cases.assign_case_user!(%{case_id: assigned.id, user_id: supporter.id}, actor: poc)

      {:ok, _lv, html} = conn |> log_in(supporter) |> live(~p"/cases")

      assert html =~ "Assigned case"
      refute html =~ "Hidden case"
    end
  end

  describe "case detail" do
    test "renders content, allows editing in draft", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Editable case"})

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")
      assert html =~ "Editable case"
      assert html =~ "Case content"

      lv
      |> form("#case-content-form", %{"form" => %{"title" => "Renamed case"}})
      |> render_submit()

      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).title == "Renamed case"
    end

    test "markdown fields preview the rendered HTML and keep unsaved edits", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "Markdown case"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      # Type into the description (unsaved), then switch that field to preview.
      lv
      |> form("#case-content-form", %{
        "form" => %{"description_md" => "Uses `zip:unzip/1` **unsafely**."}
      })
      |> render_change()

      html =
        lv
        |> element("#case-description-md button[phx-value-mode=preview]")
        |> render_click()

      assert html =~ "<code>zip:unzip/1</code>"
      assert html =~ "<strong>unsafely</strong>"

      # The textarea stays in the DOM (hidden), so submitting mid-preview
      # still saves the unsaved edit.
      lv
      |> form("#case-content-form")
      |> render_submit()

      case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)
      assert case_record.description_md == "Uses `zip:unzip/1` **unsafely**."

      # And switching back to write shows the textarea again.
      html =
        lv
        |> element("#case-description-md button[phx-value-mode=write]")
        |> render_click()

      assert html =~ "Uses `zip:unzip/1` **unsafely**."
    end

    test "the CVSS calculator scores toggle selections and persists the vector", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "CVSS case"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      # First toggle starts from the all-benign baseline (0.0 NONE), then
      # raising vulnerable-system confidentiality to High yields a real score.
      # The extra "value" => "" emulates the browser merging the clicked
      # button's empty DOM value into the payload (regression: it must not
      # clobber the selection).
      html =
        lv
        |> element(~s{#case-cvss-v4 button[phx-value-code="VC"][phx-value-selection="H"]})
        |> render_click(%{"value" => ""})

      assert html =~ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
      assert html =~ "8.7"
      assert html =~ "high"

      # Submitting the form persists the built vector through the CVSS type.
      lv
      |> form("#case-content-form")
      |> render_submit()

      case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)

      assert case_record.cvss_v4.vector ==
               "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

      assert case_record.cvss_v4.score == 8.7
      assert case_record.cvss_v4.severity == :high

      # A pasted vector updates the toggles: physical attack vector selected.
      lv
      |> element(~s{#case-cvss-v4 input[name="form[cvss_v4]"]})
      |> render_keyup(%{
        "value" => "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
      })

      assert lv
             |> element(~s{#case-cvss-v4 button[phx-value-code="AV"][phx-value-selection="P"]})
             |> render() =~ "btn-primary"

      # Garbage flags an invalid vector instead of scoring.
      html =
        lv
        |> element(~s{#case-cvss-v4 input[name="form[cvss_v4]"]})
        |> render_keyup(%{"value" => "CVSS:4.0/bogus"})

      assert html =~ "invalid vector"
    end

    test "walks the review lifecycle", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      lv |> element("button", "Request review") |> render_click()
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :review

      lv |> element("button", "Approve") |> render_click()
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :approved

      # Approved content is frozen: no edit tab remains, propose is offered.
      html = render(lv)
      refute html =~ "/cases/#{case_record.id}/edit"
      assert html =~ "/cases/#{case_record.id}/propose"

      lv |> element("button", "Reopen") |> render_click()
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :draft
    end

    test "adds an affected package through the modal", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      lv |> element("button[phx-value-type=package]", "Add package") |> render_click()
      assert render(lv) =~ "Add affected package"

      lv
      |> form("#child-form", %{
        "child" => %{
          "vendor" => "acme",
          "product" => "acme_lib",
          "repo_url" => "https://github.com/acme/acme_lib",
          "modules" => "ssh, ssl"
        }
      })
      |> render_submit()

      case_record = Ash.load!(case_record, [:affected_packages], authorize?: false)
      assert [package] = case_record.affected_packages
      assert package.modules == ["ssh", "ssl"]
      assert render(lv) =~ "acme_lib"
    end

    test "adds a reference with tag checkboxes and custom x_ tags", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      lv |> element("button[phx-value-type=reference]", "Add reference") |> render_click()
      html = render(lv)
      assert html =~ "vendor-advisory"
      assert html =~ ~s(type="checkbox")

      lv
      |> form("#child-form", %{
        "child" => %{
          "url" => "https://github.com/acme/acme_lib/security/advisories/GHSA-x",
          "tags" => ["", "vendor-advisory", "related"],
          "custom_tags" => "x_version-scheme"
        }
      })
      |> render_submit()

      case_record = Ash.load!(case_record, [:references], authorize?: false)
      assert [reference] = case_record.references
      assert reference.tags == ["vendor-advisory", "related", "x_version-scheme"]

      # Editing shows the stored tags: checkboxes reflect the standard ones,
      # the custom input carries the x_ tag.
      lv
      |> element(~s{button[phx-click=edit_child][phx-value-type=reference]}, "Edit")
      |> render_click()

      html = render(lv)
      assert html =~ ~s(value="vendor-advisory" checked)
      assert html =~ ~s(value="x_version-scheme")

      # Unchecking everything clears the tags (the hidden sentinel submits).
      lv
      |> form("#child-form", %{"child" => %{"tags" => [""], "custom_tags" => ""}})
      |> render_submit()

      case_record = Ash.load!(case_record, [:references], authorize?: false)
      assert [%{tags: []}] = case_record.references
    end

    test "references append without a position field and reorder by drag & drop", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      for url <- ["https://example.com/first", "https://example.com/second"] do
        lv |> element("button[phx-value-type=reference]", "Add reference") |> render_click()
        refute render(lv) =~ "Position (advisory first)"

        lv
        |> form("#child-form", %{"child" => %{"url" => url}})
        |> render_submit()
      end

      case_record = Ash.load!(case_record, [:references], authorize?: false)

      assert [
               %{url: "https://example.com/first", position: 0},
               %{url: "https://example.com/second", position: 1}
             ] =
               Enum.sort_by(case_record.references, & &1.position)

      # The hook pushes the ids in their new DOM order.
      [first, second] = Enum.sort_by(case_record.references, & &1.position)

      lv
      |> element("#references-rows")
      |> render_hook("reorder_references", %{"ids" => [second.id, first.id]})

      case_record = Ash.load!(case_record, [:references], authorize?: false)

      assert [
               %{url: "https://example.com/second", position: 0},
               %{url: "https://example.com/first", position: 1}
             ] =
               Enum.sort_by(case_record.references, & &1.position)

      # The rendered list follows the new order.
      html = render(lv)
      {second_at, _} = :binary.match(html, "https://example.com/second")
      {first_at, _} = :binary.match(html, "https://example.com/first")
      assert second_at < first_at
    end

    test "CWE/CAPEC rows link to the official pages and the modal autocompletes", %{
      conn: conn,
      poc: poc
    } do
      Fixtures.seed_weakness(613, "Insufficient Session Expiration")
      Fixtures.seed_weakness(79, "Improper Neutralization of Input During Web Page Generation")
      Fixtures.seed_attack_pattern(593, "Session Hijacking")

      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      # The add modal offers the catalog as a datalist…
      lv |> element("button[phx-value-type=weakness]", "Add CWE") |> render_click()
      html = render(lv)
      assert html =~ ~s(<datalist id="cwe-options">)
      assert html =~ "CWE-79 Improper Neutralization"

      # …and an autocompleted "CWE-<id> <name>" value resolves to the id.
      lv
      |> form("#child-form", %{
        "child" => %{"cwe_id" => "CWE-613 Insufficient Session Expiration"}
      })
      |> render_submit()

      lv |> element("button[phx-value-type=impact]", "Add CAPEC") |> render_click()

      lv
      |> form("#child-form", %{"child" => %{"capec_id" => "593"}})
      |> render_submit()

      case_record = Ash.load!(case_record, [:weaknesses, :impacts], authorize?: false)
      assert [%{cwe_id: 613}] = case_record.weaknesses
      assert [%{capec_id: 593}] = case_record.impacts

      # The rows link to the official definitions.
      html = render(lv)
      assert html =~ ~s(href="https://cwe.mitre.org/data/definitions/613.html")
      assert html =~ ~s(href="https://capec.mitre.org/data/definitions/593.html")
    end

    test "credits append without a position field and reorder by drag & drop", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      for name <- ["Alice Finder", "Bob Fixer"] do
        lv |> element("button[phx-value-type=credit]", "Add credit") |> render_click()
        refute render(lv) =~ ~s(name="child[position]")

        lv
        |> form("#child-form", %{"child" => %{"name" => name, "credit_type" => "finder"}})
        |> render_submit()
      end

      case_record = Ash.load!(case_record, [:credits], authorize?: false)

      assert [%{name: "Alice Finder", position: 0}, %{name: "Bob Fixer", position: 1}] =
               Enum.sort_by(case_record.credits, & &1.position)

      [alice, bob] = Enum.sort_by(case_record.credits, & &1.position)

      lv
      |> element("#credits-rows")
      |> render_hook("reorder_credits", %{"ids" => [bob.id, alice.id]})

      case_record = Ash.load!(case_record, [:credits], authorize?: false)

      assert [%{name: "Bob Fixer", position: 0}, %{name: "Alice Finder", position: 1}] =
               Enum.sort_by(case_record.credits, & &1.position)
    end

    test "posts a comment", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      lv
      |> form("form[phx-submit=post_comment]", %{"body" => "Looks good to me"})
      |> render_submit()

      assert render(lv) =~ "Looks good to me"
    end

    test "accepts a proposal from the review panel", %{conn: conn, poc: poc, supporter: supporter} do
      case_record = Fixtures.open_case(poc, %{title: "Old title"})
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :case,
            operation: :set,
            field_name: "title",
            proposed_value: %{"value" => "Proposed title"},
            reasoning: "clearer"
          },
          actor: supporter
        )

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      assert html =~ "set case.title"
      assert html =~ "Proposed title"

      lv
      |> form("#resolve-#{proposal.id}")
      |> render_submit(%{"decision" => "accept", "resolution_note" => "makes sense"})

      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).title == "Proposed title"
      assert Ash.get!(Cases.Proposal, proposal.id, authorize?: false).state == :accepted

      # Accepted proposals leave the main list for the collapsed details block.
      html = render(lv)
      assert html =~ "Accepted (1)"
      assert [before_accepted, _rest] = String.split(html, "Accepted (1)", parts: 2)
      refute before_accepted =~ "set case.title"
    end

    test "an unassigned supporter cannot open the case", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      case_record = Fixtures.open_case(poc)

      assert {:error, {:live_redirect, %{to: "/cases"}}} =
               conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}")
    end
  end

  describe "propose mode" do
    test "a frozen case defaults to view and offers a propose tab, no edit", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "Frozen case"})
      case_record = Cases.request_case_review!(case_record, actor: poc)
      case_record = Cases.approve_case!(case_record, actor: poc)

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # View is the default; Edit is unavailable, Propose is offered.
      refute html =~ "/cases/#{case_record.id}/edit"
      assert html =~ "/cases/#{case_record.id}/propose"
      refute html =~ "case-content-form"

      html = lv |> element(~s{a[href="/cases/#{case_record.id}/propose"]}) |> render_click()
      assert html =~ "your edits become new proposals"
      assert html =~ "Propose changes"

      lv
      |> form("#case-content-form", %{"form" => %{"title" => "Better frozen title"}})
      |> render_submit(%{"reasoning" => "clearer title"})

      # The case itself is untouched; the change became a proposal.
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).title == "Frozen case"

      assert [proposal] = Cases.list_open_case_proposals!(case_record.id, actor: poc)
      assert proposal.field_name == "title"
      assert proposal.proposed_value == %{"value" => "Better frozen title"}
      assert proposal.reasoning == "clearer title"
      assert render(lv) =~ "Created 1 proposal(s)."
    end

    test "open proposals show as accepted; untouched values propose nothing, edits counter", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "Stored title"})

      open =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :case,
            operation: :set,
            field_name: "title",
            proposed_value: %{"value" => "Proposed title"}
          },
          actor: poc
        )

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/propose")

      # The form carries the projected (proposed) value.
      assert lv |> element("#case-content-form input[name=\"form[title]\"]") |> render() =~
               "Proposed title"

      # Submitting untouched proposes nothing.
      lv
      |> form("#case-content-form", %{"form" => %{"title" => "Proposed title"}})
      |> render_submit()

      assert render(lv) =~ "No changes to propose."

      # Changing the projected value files a counter-proposal.
      lv
      |> form("#case-content-form", %{"form" => %{"title" => "Counter title"}})
      |> render_submit()

      proposals = Cases.list_open_case_proposals!(case_record.id, actor: poc)
      assert [counter] = Enum.reject(proposals, &(&1.id == open.id))
      assert counter.proposed_value == %{"value" => "Counter title"}
      assert counter.parent_proposal_id == open.id
    end

    test "the modal proposes inserts and edits; removals become delete proposals", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc)
      package = Fixtures.add_affected_package(poc, case_record)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/propose")

      # Propose adding a reference: no row is created, an :insert proposal is.
      lv |> element("button[phx-value-type=reference]", "Add reference") |> render_click()

      lv
      |> form("#child-form", %{
        "child" => %{"url" => "https://example.com/advisory", "tags" => ["vendor-advisory"]}
      })
      |> render_submit(%{"reasoning" => "found the advisory"})

      assert Ash.load!(case_record, [:references], authorize?: false).references == []

      assert [insert_proposal] = Cases.list_open_case_proposals!(case_record.id, actor: poc)
      assert insert_proposal.operation == :insert
      assert insert_proposal.target == :reference
      assert insert_proposal.proposed_value["value"]["url"] == "https://example.com/advisory"

      # The phantom row renders with a proposed badge.
      html = render(lv)
      assert html =~ "https://example.com/advisory"
      assert html =~ "proposed"

      # Propose editing the package: only the changed field becomes a proposal.
      lv
      |> element(~s{button[phx-value-type=package][phx-value-id="#{package.id}"]}, "Edit")
      |> render_click()

      lv
      |> form("#child-form", %{"child" => %{"vendor" => "someone-else", "product" => "acme_lib"}})
      |> render_submit()

      assert Ash.get!(Cases.AffectedPackage, package.id, authorize?: false).vendor == "acme"

      set_proposals =
        case_record.id
        |> Cases.list_open_case_proposals!(actor: poc)
        |> Enum.filter(&(&1.operation == :set))

      assert [set_proposal] = set_proposals
      assert set_proposal.target == :affected_package
      assert set_proposal.target_id == package.id
      assert set_proposal.field_name == "vendor"
      assert set_proposal.proposed_value == %{"value" => "someone-else"}

      # Propose removal files a :delete proposal instead of destroying.
      lv
      |> element(
        ~s{button[phx-value-type=package][phx-value-id="#{package.id}"]},
        "Propose removal"
      )
      |> render_click()

      assert Cases.AffectedPackage |> Ash.get(package.id, authorize?: false) |> elem(0) == :ok

      deletes =
        case_record.id
        |> Cases.list_open_case_proposals!(actor: poc)
        |> Enum.filter(&(&1.operation == :delete))

      assert [delete_proposal] = deletes
      assert delete_proposal.target_id == package.id

      # The package now renders as removal-proposed.
      assert render(lv) =~ "removal proposed"
    end
  end

  describe "diff to published record" do
    test "amendments offer a diff against the published container", %{conn: conn, poc: poc} do
      year = Date.utc_today().year
      cve_record = Fixtures.published_cve_record("CVE-#{year}-55555", "Old title")
      case_record = Fixtures.open_case(poc, %{title: "New title"})

      # Link the case to the already-published record (an amendment in progress).
      Varsel.Repo.query!(
        "UPDATE cases SET cve_record_id = $1 WHERE id = $2",
        [Ecto.UUID.dump!(cve_record.id), Ecto.UUID.dump!(case_record.id)]
      )

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      assert html =~ "Diff to published"

      lv |> element("button", "Diff to published") |> render_click()
      html = render_async(lv)

      # The published title leaves, the case title arrives.
      assert html =~ "Old title"
      assert html =~ "New title"
      assert html =~ "bg-error/10"
      assert html =~ "bg-success/10"
    end

    test "never-published cases show no diff button", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      refute html =~ "Diff to published"
    end
  end

  describe "attached reports" do
    setup %{poc: poc} do
      reporter = Fixtures.register_user("case_report_reporter")

      report =
        Varsel.CVE.submit_vulnerability_report!(
          %{
            report_json: %{"package" => "acme_lib"},
            summary: "acme_lib leaks secrets",
            confirms_criteria: true,
            confirms_in_scope: true
          },
          actor: reporter
        )

      {:ok, report} = Varsel.CVE.accept_vulnerability_report(report, %{}, actor: poc)
      %{report: report, case_id: report.case_id}
    end

    test "the case page lists attached reports in a collapsible section", %{
      conn: conn,
      poc: poc,
      case_id: case_id
    } do
      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_id}")

      assert html =~ "Reports (1)"
      assert html =~ "acme_lib leaks secrets"
      assert html =~ "case_report_reporter"
    end

    test "an assigned supporter sees the report through the case, but not directly", %{
      conn: conn,
      poc: poc,
      supporter: supporter,
      report: report,
      case_id: case_id
    } do
      Cases.assign_case_user!(%{case_id: case_id, user_id: supporter.id}, actor: poc)

      {:ok, _lv, html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_id}")

      # Visible through the case relationship (accessing_from) …
      assert html =~ "Reports (1)"
      assert html =~ "acme_lib leaks secrets"
      # … including the reporter's name, while field policies hide the rest.
      assert html =~ "case_report_reporter name"
      refute html =~ "case_report_reporter@example.com"

      # … and direct report reads/lists stay POC-only.
      assert Varsel.CVE.list_vulnerability_reports!(actor: supporter) == []

      assert {:error, %Ash.Error.Invalid{}} =
               Ash.get(Varsel.CVE.VulnerabilityReport, report.id, actor: supporter)

      # The same field scoping holds for a direct authorized load through the case.
      loaded_case =
        Cases.get_case!(case_id, actor: supporter, load: [vulnerability_reports: [:reporter]])

      [loaded_report] = loaded_case.vulnerability_reports
      assert loaded_report.reporter.name == "case_report_reporter name"
      assert %Ash.ForbiddenField{} = loaded_report.reporter.email
    end

    test "a case without reports shows no reports section", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "No reports"})

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      refute html =~ "Reports ("
    end
  end
end
