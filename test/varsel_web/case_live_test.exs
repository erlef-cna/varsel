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

    test "pipeline is the default face and shows lanes for the four active states", %{
      conn: conn,
      poc: poc
    } do
      Fixtures.open_case(poc, %{title: "Draft case"})

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases")

      assert html =~ "Draft case"
      assert html =~ "Draft"
      assert html =~ "Review"
      assert html =~ "Approved"
      assert html =~ "Publishing"
      # The band tabs, not a stat-tile filter row.
      assert html =~ "Pipeline"
      assert html =~ "Archive"
    end

    test "a POC opens a case through the band's on-demand title popover", %{conn: conn, poc: poc} do
      Fixtures.open_case(poc, %{title: "Existing case"})

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases")
      assert html =~ "Existing case"
      # The band holds only search + the "Open case" button at rest; the
      # title input is revealed on demand.
      refute html =~ "Working title"

      html = lv |> element("button", "Open case") |> render_click()
      assert html =~ "Working title"

      # Escape closes the popover without opening anything.
      html =
        lv
        |> element("div[phx-window-keydown=close_open_case]")
        |> render_keydown(%{"key" => "escape"})

      refute html =~ "Working title"

      lv |> element("button", "Open case") |> render_click()

      lv
      |> form("form[phx-submit=open_case]", %{"title" => "Fresh case"})
      |> render_submit()

      assert {path, _flash} = assert_redirect(lv)
      assert path =~ ~r{^/cases/}
    end

    test "pipeline cards show one package chip per affected package", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Chipped case"})
      Fixtures.add_affected_package(poc, case_record)

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases")

      [_before, card] = String.split(html, "Chipped case", parts: 2)
      assert card =~ "acme_lib"
    end

    test "a supporter only sees assigned cases, policy-scoped same as before", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      assigned = Fixtures.open_case(poc, %{title: "Assigned case"})
      Fixtures.open_case(poc, %{title: "Hidden case"})
      Cases.assign_case_user!(%{case_id: assigned.id, user_id: supporter.id}, actor: poc)

      {:ok, _lv, html} = conn |> log_in(supporter) |> live(~p"/cases")

      assert html =~ "Assigned case"
      refute html =~ "Hidden case"
    end

    test "faces switch via patch links and the URL carries the face", %{conn: conn, poc: poc} do
      Fixtures.open_case(poc, %{title: "Pipeline case"})
      Fixtures.archived_case(:published, "Archived case", DateTime.utc_now())

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases")
      assert html =~ "Pipeline case"
      refute html =~ "Archived case"

      html = lv |> element("a", "Archive") |> render_click()
      assert_patch(lv, ~p"/cases?face=archive&scope=all")
      assert html =~ "Archived case"
      refute html =~ "Pipeline case"

      # Deep link straight to the archive face restores it on load.
      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases?face=archive")
      assert html =~ "Archived case"
    end

    test "lanes group by state, order oldest-updated-first, and show empty lanes as \"—\"", %{
      conn: conn,
      poc: poc
    } do
      old = Fixtures.open_case(poc, %{title: "Older draft"})
      _new = Fixtures.open_case(poc, %{title: "Newer draft"})

      Ash.Seed.update!(old, %{updated_at: DateTime.add(DateTime.utc_now(), -1, :day)})

      review_case = Fixtures.open_case(poc, %{title: "In review"})
      Cases.request_case_review!(review_case, actor: poc)

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases")

      # The older draft renders before the newer one (oldest-in-state first).
      [_before, after_older] = String.split(html, "Older draft", parts: 2)
      assert String.contains?(after_older, "Newer draft")

      assert html =~ "In review"
      # Approved is empty: the lane stays, its body shows "—" right after its
      # own header (not the Publishing lane's, which follows Approved's). The
      # violet dot class is unique to the Approved lane header.
      [_before_approved, after_approved] = String.split(html, "var(--violet)", parts: 2)
      [approved_lane, _rest] = String.split(after_approved, "Publishing", parts: 2)
      assert approved_lane =~ "—"
    end

    test "a lane past 8 cards clips oldest-first with a \"Show all N\" footer that expands in place",
         %{conn: conn, poc: poc} do
      for n <- 1..9 do
        Fixtures.open_case(poc, %{title: "Draft #{n}"})
        Process.sleep(1)
      end

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases")

      assert html =~ "Show all 9"
      # Oldest-first clipping hides only the freshest intake: Draft 9 (the
      # last one opened) is clipped; Draft 1 (the oldest) always shows.
      assert html =~ "Draft 1"
      refute html =~ "Draft 9"

      html = lv |> element("button[phx-value-lane=draft]") |> render_click()
      assert html =~ "Show fewer"
      assert html =~ "Draft 9"
    end

    test "staleness: a card past its lane's threshold names the lane in its age", %{
      conn: conn,
      poc: poc
    } do
      stale_review = Fixtures.open_case(poc, %{title: "Stale review case"})
      review_case = Cases.request_case_review!(stale_review, actor: poc)

      Ash.Seed.update!(review_case, %{updated_at: DateTime.add(DateTime.utc_now(), -6, :day)})

      fresh_review = Fixtures.open_case(poc, %{title: "Fresh review case"})
      Cases.request_case_review!(fresh_review, actor: poc)

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases")

      assert html =~ "6 d in review"
      assert html =~ "text-warning"
    end

    test "review/approved cards without an assignee show the dashed needs-owner circle; draft doesn't",
         %{conn: conn, poc: poc} do
      Fixtures.open_case(poc, %{title: "Unassigned draft"})
      unassigned_review = Fixtures.open_case(poc, %{title: "Unassigned review"})
      Cases.request_case_review!(unassigned_review, actor: poc)

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases")

      # Both render; only the review card carries the needs-owner glyph.
      [_before, after_draft] = String.split(html, "Unassigned draft", parts: 2)
      [draft_card, _rest] = String.split(after_draft, "Unassigned review", parts: 2)
      refute draft_card =~ "Needs an owner"

      [_before2, after_review] = String.split(html, "Unassigned review", parts: 2)
      assert after_review =~ "Needs an owner"
    end

    test "search filters lanes in place and the inactive tab shows the cross-face match count", %{
      conn: conn,
      poc: poc
    } do
      Fixtures.open_case(poc, %{title: "bandit smuggling bug"})
      Fixtures.open_case(poc, %{title: "unrelated draft"})
      Fixtures.archived_case(:published, "bandit archived report", DateTime.utc_now())
      # A non-matching archived row: the cross-face count must evaluate it
      # without :cve_id loaded (regression: NotLoaded is truthy, crashed
      # String.downcase/2).
      Fixtures.archived_case(:published, "quiet unrelated record", DateTime.utc_now())

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases")

      html =
        lv
        |> form("#case-search", %{"query" => "bandit"})
        |> render_change()

      assert_patch(lv, ~p"/cases?q=bandit")
      assert html =~ "bandit smuggling bug"
      refute html =~ "unrelated draft"
      # The inactive Archive tab's count becomes the cross-face match count.
      assert html =~ "matches for &#39;bandit&#39;"

      # The Draft lane header shows the match count (1) while the query is
      # active — not the live total (2).
      assert lv |> element("#lane-draft") |> render() =~ ~r/tabular-nums font-bold">\s*1\s*</

      html = lv |> element("a", "Archive") |> render_click()
      assert html =~ "bandit archived report"

      # Clearing the query restores the live totals in the lane headers.
      lv |> element("a", "Pipeline") |> render_click()
      lv |> form("#case-search", %{"query" => ""}) |> render_change()
      assert lv |> element("#lane-draft") |> render() =~ ~r/tabular-nums font-bold">\s*2\s*</
    end

    test "lanes update live when a case changes state elsewhere", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Live moving case"})

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases")
      assert html =~ "Live moving case"

      # An out-of-band transition must reach the lanes via the case:all echo.
      Cases.request_case_review!(case_record, actor: poc)

      html = render(lv)
      assert html =~ "Live moving case"
      assert lv |> element("#lane-review") |> render() =~ "Live moving case"
    end

    test "zero matches on the active face points across to the archive", %{conn: conn, poc: poc} do
      Fixtures.open_case(poc, %{title: "unrelated draft"})
      Fixtures.archived_case(:published, "only in archive bandit", DateTime.utc_now())

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases?q=bandit")

      assert html =~ "No active cases match"
      assert html =~ "1 match in"
      refute html =~ "1 matches in"
      assert html =~ "Archive"
    end

    test "archive collates published + closed by archived-at descending, closed rows carry their date on state",
         %{conn: conn, poc: poc} do
      old_published =
        Fixtures.archived_case(:published, "Old published", ~U[2026-06-01 00:00:00Z])

      closed_between =
        Fixtures.archived_case(:closed, "Closed in between", ~U[2026-06-15 00:00:00Z])

      new_published =
        Fixtures.archived_case(:published, "New published", ~U[2026-07-01 00:00:00Z])

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases?face=archive")

      assert html =~ "Old published"
      assert html =~ "Closed in between"
      assert html =~ "New published"
      assert html =~ "● Closed · Jun 15"
      assert html =~ "● Published"

      # Interleaved by archived-at descending: newest published first, then
      # the closed row (Jun 15), then the oldest published row.
      new_at = html |> :binary.match("New published") |> elem(0)
      closed_at = html |> :binary.match("Closed in between") |> elem(0)
      old_at = html |> :binary.match("Old published") |> elem(0)
      assert new_at < closed_at
      assert closed_at < old_at

      [_, closed_id] = Enum.map([old_published, new_published], & &1.id)
      assert closed_id
      assert closed_between.state == :closed
    end

    test "the archive scope strip filters without resorting", %{conn: conn, poc: poc} do
      Fixtures.archived_case(:published, "A published case", DateTime.utc_now())
      Fixtures.archived_case(:closed, "A closed case", DateTime.utc_now())

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases?face=archive")
      assert html =~ "A published case"
      assert html =~ "A closed case"

      html = lv |> element("a", "Published") |> render_click()
      assert_patch(lv, ~p"/cases?face=archive&scope=published")
      assert html =~ "A published case"
      refute html =~ "A closed case"

      html = lv |> element("a", "Closed") |> render_click()
      assert_patch(lv, ~p"/cases?face=archive&scope=closed")
      assert html =~ "A closed case"
      refute html =~ "A published case"
    end

    test "archive rows navigate to the case, closed cases included", %{conn: conn, poc: poc} do
      published = Fixtures.archived_case(:published, "Nav published", DateTime.utc_now())
      closed = Fixtures.archived_case(:closed, "Nav closed", DateTime.utc_now())

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases?face=archive")

      lv |> element("tr", "Nav published") |> render_click()
      assert_redirect(lv, ~p"/cases/#{published.id}")

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases?face=archive")
      lv |> element("tr", "Nav closed") |> render_click()
      assert_redirect(lv, ~p"/cases/#{closed.id}")
    end

    test "archive paginates at 25 per page with prev/next and a jump-to-page input", %{
      conn: conn,
      poc: poc
    } do
      for n <- 1..26 do
        Fixtures.archived_case(
          :published,
          "Archived #{n}",
          DateTime.add(DateTime.utc_now(), -n, :day)
        )
      end

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases?face=archive")
      assert html =~ "26 cases"
      assert html =~ "Page 1 of 2"
      # The oldest (26th) case is on page two, not page one.
      assert html =~ "Archived 25"
      refute html =~ "Archived 26"

      # Jump-to-page re-reads: the input's submit event must land AND swap
      # the rows, not just relabel the pager.
      html =
        lv
        |> element("#archive-pager-wide form[phx-submit=jump_page]")
        |> render_submit(%{"page" => "2"})

      assert html =~ "Page 2 of 2"
      assert html =~ "Archived 26"
      refute html =~ "Archived 25"

      # Prev returns to page one with page one's rows.
      html = lv |> element("#archive-pager-wide button[phx-value-page=prev]") |> render_click()
      assert html =~ "Page 1 of 2"
      assert html =~ "Archived 25"
      refute html =~ "Archived 26"
    end

    test "deep-linking straight to page 2 of the archive restores that page", %{
      conn: conn,
      poc: poc
    } do
      for n <- 1..26 do
        Fixtures.archived_case(
          :published,
          "Archived #{n}",
          DateTime.add(DateTime.utc_now(), -n, :day)
        )
      end

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases?face=archive&page=2")

      assert html =~ "Page 2 of 2"
      assert html =~ "Archived 26"
    end

    test "empty archive shows the table card with a centered message and no pager", %{
      conn: conn,
      poc: poc
    } do
      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases?face=archive")

      assert html =~ "Nothing archived yet"
      refute html =~ "per page"
    end

    test "an entirely empty pipeline still renders all four lanes plus the helper line", %{
      conn: conn,
      poc: poc
    } do
      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases")

      assert html =~ "Draft"
      assert html =~ "Review"
      assert html =~ "Approved"
      assert html =~ "Publishing"
      assert html =~ "No active cases."
      assert html =~ "Open a case"
      assert html =~ "archive"
    end
  end

  describe "case detail" do
    test "view mode renders markdown content and cached derived ranges", %{conn: conn, poc: poc} do
      case_record =
        Fixtures.open_case(poc, %{
          title: "Markdown case",
          description_md: "Some **bold** claim",
          workarounds_md: "disable the acme integration"
        })

      package = Fixtures.add_affected_package(poc, case_record)

      channel =
        Cases.add_package_channel!(
          %{
            case_id: case_record.id,
            affected_package_id: package.id,
            purl_type: :hex,
            name: "acme_lib"
          },
          actor: poc
        )

      intro_sha = String.duplicate("a", 40)

      cache = %{
        "channels" => %{
          channel.id => %{
            "versions" => [
              %{
                "version" => "1.0.0",
                "lessThan" => "2.0.0",
                "status" => "affected",
                "versionType" => "semver"
              }
            ],
            "pending" => [],
            "issues" => []
          }
        },
        "git" => %{
          "versions" => [
            %{
              "version" => intro_sha,
              "lessThan" => "*",
              "status" => "affected",
              "versionType" => "git"
            }
          ],
          "pending" => [],
          "issues" => []
        },
        "issues" => ["no introduced boundary fact recorded"]
      }

      package
      |> Ash.Changeset.for_update(:store_derivation, %{derivation_cache: cache}, authorize?: false)
      |> Ash.update!()

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # Markdown renders as HTML, including the sections beyond the description.
      assert html =~ "<strong>bold</strong>"
      assert html =~ "Workarounds"
      assert html =~ "disable the acme integration"

      # Cached derived ranges show per channel, plus the implicit git entry.
      assert html =~ "≥ 1.0.0 &lt; 2.0.0"
      assert html =~ "github (implicit)"
      assert html =~ "≥ aaaaaaaaaaaa…"
      assert html =~ "no introduced boundary fact recorded"
      assert html =~ "derived"
    end

    test "renders content, allows editing in draft", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Editable case"})

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")
      assert html =~ "Editable case"
      assert html =~ "Summary"

      # The band kicker carries the muted opened-date fragment.
      assert html =~ "draft opened"

      # The section rail is a SectionRail-hook nav and includes Severity.
      assert html =~ ~s(phx-hook="SectionRail")
      assert html =~ ~s(href="#severity")

      # The severity card's empty state: no chip, just the invitation.
      assert html =~ "No CVSS score yet."
      assert html =~ "Open calculator"

      lv
      |> form("#case-content-form", %{"form" => %{"title" => "Renamed case"}})
      |> render_submit()

      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).title == "Renamed case"
      assert render(lv) =~ "Renamed case"
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

      # Saving closes the editor; reopening shows the saved markdown.
      html =
        lv
        |> element(~s{button[phx-click=edit_section][phx-value-section=summary]})
        |> render_click()

      assert html =~ "Uses `zip:unzip/1` **unsafely**."
    end

    test "the CVSS calculator scores toggle selections and persists the vector", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "CVSS case"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # The calculator is the Severity card's own editor.
      lv
      |> element(~s{button[phx-click=edit_section][phx-value-section=severity]})
      |> render_click()

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
      assert html =~ "HIGH 8.7"

      # Submitting the form persists the built vector through the CVSS type.
      lv
      |> form("#case-severity-form")
      |> render_submit()

      case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)

      assert case_record.cvss_v4.vector ==
               "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

      assert case_record.cvss_v4.score == 8.7
      assert case_record.cvss_v4.severity == :high

      # At rest the card shows one tinted chip (rating + score) beside the
      # truncated mono vector.
      html = render(lv)
      assert html =~ "sev-high"
      assert html =~ "HIGH 8.7"
      assert html =~ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

      # Saving closes the editor; reopen to keep working with the calculator.
      lv
      |> element(~s{button[phx-click=edit_section][phx-value-section=severity]})
      |> render_click()

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

      # Approved content is frozen: suggesting is forced on.
      assert render(lv) =~ "Suggest: on"

      lv |> element("button", "Reopen") |> render_click()
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :draft
      assert render(lv) =~ "Suggest: off"
    end

    test "adds an affected package through the modal", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      lv |> element("button[phx-value-type=package]", "Custom package") |> render_click()
      assert render(lv) =~ "Add affected package"

      lv |> element("button[phx-click=add_program_file]") |> render_click()

      lv
      |> form("#child-form", %{
        "child" => %{
          "vendor" => "acme",
          "product" => "acme_lib",
          "repo_url" => "https://github.com/acme/acme_lib",
          "program_files" => %{
            "0" => %{
              "path" => "lib/acme.ex",
              "modules" => "ssh, ssl",
              "routines" => "ssh:connect/2"
            }
          }
        }
      })
      |> render_submit()

      case_record = Ash.load!(case_record, [:affected_packages], authorize?: false)
      assert [package] = case_record.affected_packages

      assert [%{path: "lib/acme.ex", modules: ["ssh", "ssl"], routines: ["ssh:connect/2"]}] =
               package.program_files

      assert render(lv) =~ "acme_lib"

      # Editing renders the stored rows as nested inputs and round-trips.
      lv
      |> element(~s{button[phx-value-type=package][phx-value-id="#{package.id}"]}, "Edit")
      |> render_click()

      assert lv |> element(~s{input[name="child[program_files][0][path]"]}) |> render() =~
               "lib/acme.ex"

      assert lv |> element(~s{input[name="child[program_files][0][modules]"]}) |> render() =~
               "ssh, ssl"

      lv
      |> form("#child-form", %{
        "child" => %{
          "program_files" => %{
            "0" => %{"path" => "lib/acme.ex", "modules" => "ssh", "routines" => ""}
          }
        }
      })
      |> render_submit()

      package = Ash.get!(Cases.AffectedPackage, package.id, authorize?: false)
      assert [%{path: "lib/acme.ex", modules: ["ssh"], routines: []}] = package.program_files
      assert render(lv) =~ "acme_lib"
    end

    test "adds an Erlang/OTP package through the preset modal", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      lv |> element("button[phx-value-type=package_otp]", "Erlang/OTP") |> render_click()
      assert render(lv) =~ "Add Erlang/OTP package"

      intro_sha = String.duplicate("a", 40)
      fix_sha = String.duplicate("b", 40)

      lv |> element("button[phx-click=add_program_file]") |> render_click()

      lv
      |> form("#child-form", %{
        "child" => %{
          "applications" => "ssh, ssl",
          "introduced_commit" => intro_sha,
          "fixed_commits" => fix_sha,
          "program_files" => %{
            "0" => %{
              "path" => "lib/ssh/src/ssh_sftpd.erl",
              "modules" => "ssh_sftpd",
              "routines" => "ssh_sftpd:handle_op/4"
            }
          }
        }
      })
      |> render_submit()

      case_record =
        Ash.load!(case_record, [affected_packages: [:channels, :version_events]], authorize?: false)

      assert [package] = case_record.affected_packages
      assert package.vendor == "Erlang"
      assert package.product == "OTP"
      assert [%{name: "ssh"}, %{name: "ssl"}] = package.channels

      assert MapSet.new(package.version_events, &{&1.event, &1.commit_sha}) ==
               MapSet.new([{:introduced, intro_sha}, {:fixed, fix_sha}])

      assert render(lv) =~ "Erlang / OTP"
    end

    test "adds a channel-scoped boundary fact through the modal", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      package =
        Cases.add_otp_affected_package!(
          %{case_id: case_record.id, applications: ["inets", "ftp"]},
          actor: poc,
          load: [:channels]
        )

      [inets_channel, _ftp_channel] = package.channels

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/edit")

      lv
      |> element(~s{button[phx-value-affected_package_id="#{package.id}"]}, "Add boundary")
      |> render_click()

      # The modal offers the package's channels for scoping.
      html = render(lv)
      assert html =~ "All channels (package-wide)"
      assert html =~ "pkg:otp/inets"

      lv
      |> form("#child-form", %{
        "child" => %{
          "event" => "fixed",
          "version" => "7.0",
          "package_channel_id" => inets_channel.id,
          "note" => "ftp code moved out of inets"
        }
      })
      |> render_submit()

      package = Ash.load!(package, [:version_events], authorize?: false)
      assert [event] = package.version_events
      assert event.event == :fixed
      assert event.version == "7.0"
      assert event.package_channel_id == inets_channel.id

      # The events table shows the scope badge.
      assert render(lv) =~ "pkg:otp/inets"
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
      refute render(lv) =~ ~s(value="vendor-advisory" checked)
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

      # The rendered list follows the new order.
      html = render(lv)
      {bob_at, _} = :binary.match(html, "Bob Fixer")
      {alice_at, _} = :binary.match(html, "Alice Finder")
      assert bob_at < alice_at
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
      assert html =~ "case.title"
      assert html =~ "Proposed title"

      lv
      |> form("#resolve-#{proposal.id}")
      |> render_submit(%{"decision" => "accept", "resolution_note" => "makes sense"})

      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).title == "Proposed title"
      assert Ash.get!(Cases.Proposal, proposal.id, authorize?: false).state == :accepted

      # Resolved proposals leave the inline card and the rail queue for the
      # collapsed disclosure at the bottom of the center column.
      html = render(lv)
      assert html =~ "No open suggestions."
      assert html =~ "Resolved suggestions (1)"
      assert [before_resolved, _rest] = String.split(html, "Resolved suggestions (1)", parts: 2)
      refute before_resolved =~ "set case.title"
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

    test "an open suggestion renders inline in its owning section card, and the rail Jump link anchors to it",
         %{conn: conn, poc: poc, supporter: supporter} do
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

      # The card sits inside the Summary section, carries a stable id, and
      # shows the mono field chip + author + diff — not a bottom aggregate.
      [_before, after_summary_heading] = String.split(html, ">Summary<", parts: 2)
      assert after_summary_heading =~ ~s(id="suggestion-#{proposal.id}")
      assert after_summary_heading =~ "case.title"
      assert after_summary_heading =~ supporter.name
      assert after_summary_heading =~ "Old title"
      assert after_summary_heading =~ "Proposed title"

      # The rail's compact queue row jumps straight to the inline card.
      assert html =~ ~s(href="#suggestion-#{proposal.id}")
      assert html =~ "Jump"

      # Decline's note input stays hidden until the Decline button is
      # clicked (a client-side JS.show/hide toggle) — it is not a
      # permanently visible input.
      assert lv
             |> element(~s{#resolve-#{proposal.id} input[name="resolution_note"]})
             |> render() =~ "hidden"
    end

    test "a one-word change to a long text renders as a merged inline word diff, not stacked blocks",
         %{conn: conn, poc: poc, supporter: supporter} do
      old_description =
        "Bandit's HTTP/1 parser accepted chunk extensions containing bare CR characters, " <>
          "allowing a malformed request body to be read differently by Bandit and by upstream proxies."

      new_description = String.replace(old_description, "malformed", "crafted")

      case_record = Fixtures.open_case(poc, %{description_md: old_description})
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      Cases.create_case_proposal!(
        %{
          case_id: case_record.id,
          target: :case,
          operation: :set,
          field_name: "description_md",
          proposed_value: %{"value" => new_description}
        },
        actor: supporter
      )

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # The changed word appears as adjacent del/ins spans...
      assert html =~ ~s(line-through decoration-error/45">malformed</span>)
      assert html =~ ~s(bg-success/15 text-success">crafted</span>)

      # ...and the unchanged tail renders once in the merged body — not
      # duplicated across a red block and a green block. (It appears a
      # second time on the page only as the section's own field value.)
      unchanged_tail = "request body to be read differently by Bandit and by upstream proxies."

      suggestion_html =
        html |> String.split(~s(class="rounded-md border border-base-300)) |> Enum.at(1)

      assert length(String.split(suggestion_html, unchanged_tail)) == 2
    end

    test "runs of untouched paragraphs collapse behind a fold row, revealed client-side", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      old_description =
        Enum.join(
          [
            "First paragraph has a typo in it.",
            "Second paragraph stays exactly the same across both versions.",
            "Third paragraph also stays identical, word for word, untouched.",
            "Last paragraph also has a typo right here."
          ],
          "\n\n"
        )

      new_description =
        old_description
        |> String.replace("has a typo in it", "has a typoo in it")
        |> String.replace("typo right here", "typoo right here")

      case_record = Fixtures.open_case(poc, %{description_md: old_description})
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      Cases.create_case_proposal!(
        %{
          case_id: case_record.id,
          target: :case,
          operation: :set,
          field_name: "description_md",
          proposed_value: %{"value" => new_description}
        },
        actor: supporter
      )

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # Both changed paragraphs render in full with their word diffs.
      assert html =~ ~s(>typo</span>)
      assert html =~ ~s(>typoo</span>)

      # The two untouched middle paragraphs sit behind one fold row; the
      # content is already in the DOM (client-side JS.toggle, no round
      # trip) but hidden.
      assert html =~ "2 unchanged paragraphs"

      fold_content = lv |> element(~s{[id^="fold-"][id$="-content"]}) |> render()
      assert fold_content =~ "hidden"
      assert fold_content =~ "Second paragraph stays exactly the same"
      assert fold_content =~ "Third paragraph also stays identical"
    end

    test "a CVSS vector suggestion stays stacked but emphasizes the changed metric", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      old_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
      new_vector = String.replace(old_vector, "AV:N", "AV:L")

      case_record = Fixtures.open_case(poc, %{cvss_v4: old_vector})
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      Cases.create_case_proposal!(
        %{
          case_id: case_record.id,
          target: :case,
          operation: :set,
          field_name: "cvss_v4",
          proposed_value: %{"value" => new_vector}
        },
        actor: supporter
      )

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # Still the stacked rows (whole-row tints), not a merged body...
      assert html =~ "line-through decoration-error/40"

      # ...with the one changed metric emphasized inside each row.
      assert html =~ ~s(bg-error/25">AV:N</span>)
      assert html =~ ~s(bg-success/25">AV:L</span>)
    end

    test "a suggestion's reply thread is collapsed behind its reply count", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      case_record = Fixtures.open_case(poc, %{title: "Old title"})
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :case,
            operation: :set,
            field_name: "title",
            proposed_value: %{"value" => "Proposed title"}
          },
          actor: supporter
        )

      Cases.post_case_comment!(
        %{case_id: case_record.id, proposal_id: proposal.id, body: "sounds reasonable"},
        actor: poc
      )

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # The thread renders collapsed (a client-side toggle, not a server
      # round trip) behind the reply count.
      assert html =~ "1 reply"
      assert lv |> element("#suggestion-#{proposal.id}-thread.hidden") |> has_element?()
      assert lv |> element("#suggestion-#{proposal.id}-thread") |> render() =~ "sounds reasonable"
    end

    test "People lists real assignment rows with a role word, avatar first", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: poc.id}, actor: poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      assert html =~ "POC"
      assert html =~ "supporter"
      assert html =~ poc.name
      assert html =~ supporter.name
    end
  end

  describe "propose mode" do
    test "a frozen case forces suggest mode; edits become proposals", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "Frozen case"})
      case_record = Cases.request_case_review!(case_record, actor: poc)
      case_record = Cases.approve_case!(case_record, actor: poc)

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # Suggesting is forced on the frozen case; nothing is being edited yet.
      assert html =~ "Suggest: on"
      refute html =~ "case-content-form"

      html =
        lv
        |> element(~s{button[phx-click=edit_section][phx-value-section=summary]})
        |> render_click()

      assert html =~ "your edits become proposals"
      assert html =~ "Suggest changes"

      lv
      |> form("#case-content-form", %{"form" => %{"title" => "Better frozen title"}})
      |> render_submit(%{"reasoning" => "clearer title"})

      # The case itself is untouched; the change became a proposal.
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).title == "Frozen case"

      assert [proposal] = Cases.list_open_case_proposals!(case_record.id, actor: poc)
      assert proposal.field_name == "title"
      assert proposal.proposed_value == %{"value" => "Better frozen title"}
      assert proposal.reasoning == "clearer title"

      # The suggestion card renders as an old → new diff, not a JSON blob.
      html = render(lv)
      assert html =~ "Created 1 proposal(s)."
      assert html =~ "line-through decoration-error/40"
      assert html =~ "Better frozen title"
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
      assert render(lv) =~ "Created 1 proposal(s)."
    end

    test "the preset modal files a preset :insert proposal", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/propose")

      lv |> element("button[phx-value-type=package_gleam]", "Gleam") |> render_click()

      fix_sha = String.duplicate("b", 40)

      lv |> element("button[phx-click=add_program_file]") |> render_click()

      lv
      |> form("#child-form", %{
        "child" => %{
          "fixed_commits" => fix_sha,
          "program_files" => %{
            "0" => %{"path" => "compiler-core/src/docs.rs", "modules" => "compiler-core"}
          }
        }
      })
      |> render_submit(%{"reasoning" => "gleam is affected"})

      # No row is created; the preset travels in the proposal payload.
      assert Ash.load!(case_record, [:affected_packages], authorize?: false).affected_packages ==
               []

      assert [proposal] = Cases.list_open_case_proposals!(case_record.id, actor: poc)
      assert proposal.operation == :insert
      assert proposal.target == :affected_package

      assert proposal.proposed_value == %{
               "value" => %{
                 "preset" => "gleam",
                 "fixed_commits" => [fix_sha],
                 "program_files" => [
                   %{
                     "path" => "compiler-core/src/docs.rs",
                     "modules" => ["compiler-core"],
                     "routines" => []
                   }
                 ]
               }
             }

      # The phantom row shows the preset's constants.
      html = render(lv)
      assert html =~ "Gleam / Gleam"
      assert html =~ "proposed"
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

      # The diff lives in the preview slide-over.
      refute html =~ "Diff to published"
      lv |> element("button", "Preview") |> render_click()
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

    test "never-published cases show no diff button in the preview", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      lv |> element("button", "Preview") |> render_click()
      refute render_async(lv) =~ "Diff to published"
    end
  end

  describe "preview slide-over" do
    test "validation renders per-check rows with blocker deep links, not an alert box", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "Preview case", description_md: "desc"})

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # Publish does not live in the band.
      refute html =~ "Publish to MITRE"

      lv |> element("button", "Preview") |> render_click()
      html = render_async(lv)

      # Blockers are ✗ rows with per-section links — no alert/callout box.
      refute html =~ "alert-warning"
      assert html =~ "✗"
      assert html =~ "no references recorded"
      assert html =~ ~s(href="#references")
      assert html =~ "Go to references"
      assert html =~ "CVSS v4 vector is missing"
      assert html =~ "Go to severity"

      # Validation runs against a placeholder CVE ID (no assignment needed), so
      # the per-check rows render alongside the blockers.
      assert html =~ "cvelint"
      assert html =~ "CVE record schema"
      assert html =~ "Hex packages exist"
    end

    test "the Rendered JSON tab shows the open, syntax-tinted CNA container", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc, %{title: "JSON case", description_md: "desc"})

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      lv |> element("button", "Preview") |> render_click()
      render_async(lv)

      html = lv |> element("button", "Rendered JSON") |> render_click()

      # The JSON is open (no <details>), Lumis-highlighted: keys are
      # .l-property tokens, string values .l-string.
      refute html =~ "CNA container JSON"
      assert html =~ ~s(<span class="l-property">&quot;descriptions&quot;</span>)
      assert html =~ ~s(<span class="l-string">)
    end

    test "publish is visually gated in the footer while blockers exist", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Gated case", description_md: "desc"})
      case_record = Cases.request_case_review!(case_record, actor: poc)
      Cases.approve_case!(case_record, actor: poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
      lv |> element("button", "Preview") |> render_click()
      html = render_async(lv)

      assert html =~ "Publish to MITRE"
      assert html =~ "opacity-45"
      assert html =~ "blocking publish"
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
