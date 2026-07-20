# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.VarselLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Accounts.User
  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.MitreCveApi

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

  test "'Sync with MITRE' imports new records and then syncs published ones", %{conn: conn} do
    poc = register("poc", :poc)
    cve_id = "CVE-#{@year}-1010"

    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{
        "cveId" => cve_id,
        "state" => "PUBLISHED",
        "dateUpdated" => "#{@year}-01-02T00:00:00.000Z"
      },
      "containers" => %{"cna" => %{"title" => "Imported thing"}}
    }

    Req.Test.stub(MitreCveApi, fn conn ->
      conn = Plug.Conn.fetch_query_params(conn)

      cond do
        conn.method == "GET" && String.ends_with?(conn.request_path, "/cve-id") ->
          entries = if conn.query_params["page"] == "1", do: [%{"cve_id" => cve_id}], else: []
          Req.Test.json(conn, %{"cve_ids" => entries})

        conn.method == "GET" ->
          Req.Test.json(conn, cve_json)

        true ->
          Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves/manage")

    lv |> element("button", "Sync with MITRE") |> render_click()
    render_async(lv, 5000)

    assert render(lv) =~ "MITRE import and sync finished."

    record =
      CveRecord
      |> Ash.read!(authorize?: false, load: [:cve_id])
      |> Enum.find(&(&1.cve_id == cve_id))

    assert record.state == :published
    # last_synced_at is only written by :sync_from_mitre, proving the sync ran
    # after the import brought the record in.
    assert %DateTime{} = record.last_synced_at
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
