# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.VarselLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Accounts.User
  alias Varsel.CVE.CveRecord

  @year Date.utc_today().year

  defp register(handle, role) do
    user =
      Ash.create!(
        User,
        %{
          user_info: %{
            "sub" => System.unique_integer([:positive]),
            "preferred_username" => handle,
            "name" => "#{handle} name",
            "email" => "#{handle}@example.com"
          },
          oauth_tokens: %{"access_token" => "gho_token"}
        },
        action: :register_with_github,
        authorize?: false
      )

    if role && role != user.role do
      Ash.update!(user, %{role: role}, action: :set_role, authorize?: false)
    else
      user
    end
  end

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  defp reserved_record(cve_id) do
    reservation_json = %{
      "cve_id" => cve_id,
      "cve_year" => to_string(@year),
      "owning_cna" => "EEF",
      "reserved" => "#{@year}-01-01T00:00:00.000Z",
      "state" => "RESERVED"
    }

    Ash.create!(CveRecord, %{reservation_json: reservation_json},
      action: :reserve,
      authorize?: false
    )
  end

  defp published_record(cve_id, title) do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{"cveId" => cve_id, "state" => "PUBLISHED"},
      "containers" => %{"cna" => %{"title" => title}}
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  test "a POC sees records in every state", %{conn: conn} do
    poc = register("poc", :poc)
    reserved_record("CVE-#{@year}-1001")
    published_record("CVE-#{@year}-1002", "Published thing")

    {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cves/manage")

    assert html =~ "CVE Management"
    assert html =~ "CVE-#{@year}-1001"
    assert html =~ "reserved"
    assert html =~ "CVE-#{@year}-1002"
    assert html =~ "Published thing"
  end

  test "'Reserve a new one' moves a reserved row to draft", %{conn: conn} do
    poc = register("poc", :poc)
    record = reserved_record("CVE-#{@year}-1003")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves/manage")

    lv |> element("button", "Reserve a new one") |> render_click()

    assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
  end

  test "'Reserve a new one' with an empty pool flashes an error", %{conn: conn} do
    poc = register("poc", :poc)
    published_record("CVE-#{@year}-1004", "Only published")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves/manage")

    html = lv |> element("button", "Reserve a new one") |> render_click()

    assert html =~ "No reserved IDs in the pool."
  end

  test "the list updates live when a record changes out-of-band", %{conn: conn} do
    poc = register("poc", :poc)
    record = reserved_record("CVE-#{@year}-1005")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves/manage")

    refute has_element?(lv, ~s(span.badge), "draft")

    Ash.update!(record, %{}, action: :assign, authorize?: false)

    assert render(lv) =~ "draft"
  end

  test "a non-POC is redirected away", %{conn: conn} do
    register("first", :poc)
    supporter = register("supporter", :supporter)

    assert {:error, {:redirect, %{to: "/"}}} =
             conn |> log_in(supporter) |> live(~p"/cves/manage")
  end

  test "an anonymous visitor is redirected to sign in", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/sign-in"}}} = live(conn, ~p"/cves/manage")
  end

  describe "edit page" do
    test "renders the record's cve_json as pretty JSON", %{conn: conn} do
      poc = register("poc", :poc)
      record = published_record("CVE-#{@year}-2001", "Editable")

      {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cves/manage/#{record.id}")

      assert html =~ "Edit CVE-#{@year}-2001"
      assert html =~ "CVE_RECORD"
      assert html =~ "Editable"
    end

    test "invalid JSON shows an error and keeps the edited text", %{conn: conn} do
      poc = register("poc", :poc)
      record = published_record("CVE-#{@year}-2002", "Editable")

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves/manage/#{record.id}")

      html =
        lv
        |> form("form", %{"cve_json" => "{not valid json"})
        |> render_submit()

      assert html =~ "Invalid JSON."
      assert html =~ "{not valid json"
    end
  end
end
