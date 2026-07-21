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

    {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/cves")

    assert html =~ "CVE Management"
    assert html =~ "CVE-#{@year}-1001"
    assert html =~ "reserved"
    assert html =~ "CVE-#{@year}-1002"
    assert html =~ "Published thing"
  end

  test "filters by state and searches by CVE ID or title", %{conn: conn} do
    poc = register("poc", :poc)
    reserved_record("CVE-#{@year}-1001")
    published_record("CVE-#{@year}-1002", "Published thing")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves")

    html = lv |> element("button[phx-value-filter=published]") |> render_click()
    assert html =~ "Published thing"
    refute html =~ "CVE-#{@year}-1001"

    html = lv |> element("button[phx-value-filter=all]") |> render_click()
    assert html =~ "CVE-#{@year}-1001"

    html =
      lv
      |> form("#cve-record-search", %{"query" => "published TH"})
      |> render_change()

    assert html =~ "Published thing"
    refute html =~ "CVE-#{@year}-1001"
  end

  test "paginates past 25 records", %{conn: conn} do
    poc = register("poc", :poc)
    for n <- 1001..1030, do: reserved_record("CVE-#{@year}-#{n}")

    {:ok, lv, html} = conn |> log_in(poc) |> live(~p"/cves")

    assert html =~ "30 records"
    assert html =~ "Page 1 of 2"

    html = lv |> element("button[phx-value-page=next]") |> render_click()
    assert html =~ "Page 2 of 2"
  end

  test "rejecting a record goes through the confirmation modal", %{conn: conn} do
    poc = register("poc", :poc)
    record = reserved_record("CVE-#{@year}-1005")

    Req.Test.stub(MitreCveApi, fn conn ->
      if conn.method == "PUT" do
        Req.Test.json(conn, %{"message" => "CVE ID rejected"})
      else
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves")

    lv |> element(~s{button[phx-value-id="#{record.id}"]}, "Reject…") |> render_click()
    assert render(lv) =~ "Reject CVE-#{@year}-1005"

    lv
    |> form("#reject-modal form", %{"rejection_reason" => "duplicate assignment"})
    |> render_submit()

    assert Ash.get!(CveRecord, record.id, authorize?: false).state == :rejected
    refute render(lv) =~ "Reject CVE-#{@year}-1005"
  end

  test "'Reserve a new one' moves a reserved row to draft", %{conn: conn} do
    poc = register("poc", :poc)
    record = reserved_record("CVE-#{@year}-1003")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves")

    lv |> element("button", "Reserve a new one") |> render_click()

    assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
    assert render(lv) =~ "draft"
  end

  test "'Reserve a new one' with an empty pool flashes an error", %{conn: conn} do
    poc = register("poc", :poc)
    published_record("CVE-#{@year}-1004", "Only published")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves")

    html = lv |> element("button", "Reserve a new one") |> render_click()

    assert html =~ "No reserved IDs in the pool."
  end

  test "'Sync with MITRE' imports, syncs published records, and syncs the pool", %{conn: conn} do
    poc = register("poc", :poc)
    cve_id = "CVE-#{@year}-1010"
    reserved_cve_id = "CVE-#{@year}-1011"

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

    reservation_json = %{
      "cve_id" => reserved_cve_id,
      "cve_year" => to_string(@year),
      "owning_cna" => "EEF",
      "reserved" => "#{@year}-01-01T00:00:00.000Z",
      "state" => "RESERVED"
    }

    Req.Test.stub(MitreCveApi, fn conn ->
      conn = Plug.Conn.fetch_query_params(conn)

      cond do
        conn.method == "GET" && String.ends_with?(conn.request_path, "/cve-id") ->
          entries =
            case {conn.query_params["state"], conn.query_params["page"]} do
              {"PUBLISHED", "1"} -> [%{"cve_id" => cve_id}]
              {"RESERVED", "1"} -> [reservation_json]
              _other -> []
            end

          Req.Test.json(conn, %{"cve_ids" => entries})

        conn.method == "GET" ->
          Req.Test.json(conn, cve_json)

        true ->
          Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves")

    lv |> element("button", "Sync with MITRE") |> render_click()
    render_async(lv, 5000)

    assert render(lv) =~ "MITRE import and sync finished."

    by_id =
      CveRecord
      |> Ash.read!(authorize?: false, load: [:cve_id])
      |> Map.new(&{&1.cve_id, &1})

    assert by_id[cve_id].state == :published
    # last_synced_at is only written by :sync_from_mitre, proving the sync ran
    # after the import brought the record in.
    assert %DateTime{} = by_id[cve_id].last_synced_at

    assert by_id[reserved_cve_id].state == :reserved
  end

  test "the list updates live when a record changes out-of-band", %{conn: conn} do
    poc = register("poc", :poc)
    record = reserved_record("CVE-#{@year}-1005")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cves")

    refute has_element?(lv, ~s(span.badge), "draft")

    Ash.update!(record, %{}, action: :assign, authorize?: false)

    assert render(lv) =~ "draft"
  end

  test "a non-POC sees only published records and no management controls", %{conn: conn} do
    register("first", :poc)
    supporter = register("supporter", :supporter)
    reserved_record("CVE-#{@year}-1001")
    published_record("CVE-#{@year}-1002", "Published thing")

    {:ok, _lv, html} = conn |> log_in(supporter) |> live(~p"/cves")

    assert html =~ "Issued CVEs"
    assert html =~ "Published thing"
    refute html =~ "CVE-#{@year}-1001"
    refute html =~ "Reserve a new one"
    refute html =~ "Reject…"
  end

  test "an anonymous visitor sees the public list", %{conn: conn} do
    reserved_record("CVE-#{@year}-1001")
    published_record("CVE-#{@year}-1002", "Published thing")

    {:ok, _lv, html} = live(conn, ~p"/cves")

    assert html =~ "Issued CVEs"
    assert html =~ "Published thing"
    refute html =~ "CVE-#{@year}-1001"
  end

  test "the old management path redirects to the merged list", %{conn: conn} do
    poc = register("poc", :poc)

    conn = conn |> log_in(poc) |> get(~p"/cves/manage")
    assert redirected_to(conn) == ~p"/cves"
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
