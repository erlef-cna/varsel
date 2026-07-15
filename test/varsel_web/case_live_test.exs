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

      {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")
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

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

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

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      # First toggle starts from the all-benign baseline (0.0 NONE), then
      # raising vulnerable-system confidentiality to High yields a real score.
      html =
        lv
        |> element(~s{#case-cvss-v4 button[phx-value-code="VC"][phx-value-value="H"]})
        |> render_click()

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
             |> element(~s{#case-cvss-v4 button[phx-value-code="AV"][phx-value-value="P"]})
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

      html = render(lv)
      assert html =~ "frozen"

      lv |> element("button", "Reopen") |> render_click()
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :draft
    end

    test "adds an affected package through the modal", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

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
end
