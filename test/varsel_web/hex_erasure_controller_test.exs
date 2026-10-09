# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.HexErasureControllerTest do
  use VarselWeb.ConnCase, async: true

  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.Fixtures
  alias Varsel.HexPm
  alias VarselWeb.HexServiceTokenFixture

  setup do
    Req.Test.stub(HexPm, fn conn ->
      case conn.path_info do
        ["api", "users", username, "contact"] when username in ["gone", "kept"] ->
          Req.Test.json(conn, %{
            "username" => username,
            "name" => "#{username} name",
            "email" => "#{username}@example.com"
          })

        ["api", "users", "renamed", "contact"] ->
          Req.Test.json(conn, %{
            "username" => "renamed",
            "name" => nil,
            "email" => "Gone@Example.com"
          })

        _unknown ->
          Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    Req.Test.stub(Varsel.Accounts.GitHub, fn conn ->
      Req.Test.json(conn, %{"login" => "gone_on_github", "email" => "gone@example.com"})
    end)

    :ok
  end

  defp token, do: HexServiceTokenFixture.sign(url(~p"/api/hex/erasures"))

  defp erase(conn, payload, token \\ token()) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer #{token}")
    |> post(~p"/api/hex/erasures", payload)
  end

  defp person(username, attrs \\ %{}) do
    Map.merge(
      %{
        role: :maintainer,
        strategy: :hex,
        username: username,
        name: "#{username} name",
        email: "#{username}@example.com"
      },
      attrs
    )
  end

  defp report!(participants) do
    CVE.submit_hex_vulnerability_report!(
      %{
        report_json: %{"report" => "Bad."},
        summary: "Unsafe parsing",
        participants: participants
      },
      authorize?: false
    )
  end

  defp participants do
    CVE.ReportParticipant
    |> Ash.read!(authorize?: false)
    |> Map.new(&{{&1.strategy, to_string(&1.username), &1.role}, &1})
  end

  describe "an erasure hex.pm sends" do
    test "clears the name and address on the participants hex.pm named", %{conn: conn} do
      report!([
        person("Gone", %{role: :reporter}),
        person("gone"),
        person("kept"),
        person("gone", %{strategy: :github})
      ])

      conn = erase(conn, %{"username" => "gone", "email" => nil})

      assert response(conn, 204) == ""

      rows = participants()

      for key <- [{:hex, "Gone", :reporter}, {:hex, "gone", :maintainer}] do
        assert %{name: nil, email: nil} = rows[key]
      end

      assert %{name: "kept name", email: "kept@example.com"} = rows[{:hex, "kept", :maintainer}]
      assert %{name: "gone name"} = rows[{:github, "gone", :maintainer}]
    end

    test "also matches the address, whatever its casing", %{conn: conn} do
      report!([person("renamed", %{email: "Gone@Example.com"})])

      assert conn |> erase(%{"username" => "gone"}) |> response(204)
      assert %{name: "renamed name"} = participants()[{:hex, "renamed", :maintainer}]

      assert build_conn()
             |> erase(%{"username" => "gone", "email" => "gone@example.com"})
             |> response(204)

      assert %{name: nil, email: nil, username: username} =
               participants()[{:hex, "renamed", :maintainer}]

      assert to_string(username) == "renamed"
    end

    test "has no name to clear in any version, including those of spent participants" do
      report!([person("gone"), person("kept")])

      [spent] =
        [person("gone", %{role: :reporter})]
        |> report!()
        |> Ash.load!([:participants], authorize?: false)
        |> Map.fetch!(:participants)

      CVE.spend_report_participant!(spent, authorize?: false)

      versions = Ash.read!(CVE.ReportParticipant.Version)
      assert Enum.any?(versions, &(&1.version_source_id == spent.id))

      for version <- versions do
        refute Map.has_key?(version.changes, "name")
        refute Map.has_key?(version.changes, "email")
      end
    end

    test "clears the address on hex.pm invites and cancels a queued invite email", %{conn: conn} do
      poc = Fixtures.register_user("erasure_poc", :poc)
      queued = Fixtures.open_case(poc)
      emailed = Fixtures.open_case(poc)
      other = Fixtures.open_case(poc)

      Cases.invite_to_case!(%{case_id: emailed.id, strategy: :hex, username: "gone"}, actor: poc)
      Oban.drain_queue(queue: :default, with_recursion: true)
      assert_received {:email, %{to: [{"", "gone@example.com"}]}}

      Cases.invite_to_case!(%{case_id: queued.id, strategy: :hex, username: "gone"}, actor: poc)
      Cases.invite_to_case!(%{case_id: queued.id, strategy: :hex, username: "kept"}, actor: poc)
      Cases.invite_to_case!(%{case_id: other.id, strategy: :hex, username: "renamed"}, actor: poc)

      Cases.invite_to_case!(%{case_id: queued.id, strategy: :github, username: "gone_on_github"},
        actor: poc
      )

      assert conn
             |> erase(%{"username" => "GONE", "email" => "gone@example.com"})
             |> response(204)

      invites =
        Map.new(Cases.list_case_invites!(actor: poc), &{{&1.case_id, to_string(&1.username)}, &1})

      assert %{email: nil, email_status: :erased} = invites[{queued.id, "gone"}]
      assert %{email: nil, email_status: :sent} = invites[{emailed.id, "gone"}]
      assert %{email_status: :pending} = invites[{queued.id, "kept"}]
      assert %{email: nil, email_status: :erased} = invites[{other.id, "renamed"}]
      assert to_string(invites[{queued.id, "gone_on_github"}].email) == "gone@example.com"

      Oban.drain_queue(queue: :default, with_recursion: true)

      refute_received {:email, %{to: [{"", "gone@example.com"}]}}
      assert_received {:email, %{to: [{"", "kept@example.com"}]}}
    end

    test "is answered the same when nothing matches, and when repeated", %{conn: conn} do
      report!([person("gone")])

      assert conn |> erase(%{"username" => "nobody"}) |> response(204)
      assert build_conn() |> erase(%{"username" => "gone"}) |> response(204)
      assert build_conn() |> erase(%{"username" => "gone"}) |> response(204)

      assert %{name: nil} = participants()[{:hex, "gone", :maintainer}]
    end
  end

  describe "is refused when" do
    setup do
      report!([person("gone")])
      :ok
    end

    defp untouched? do
      match?(%{name: "gone name"}, participants()[{:hex, "gone", :maintainer}])
    end

    test "no token is presented", %{conn: conn} do
      conn = post(conn, ~p"/api/hex/erasures", %{"username" => "gone"})

      assert json_response(conn, 401) == %{"error" => "invalid_token"}
      assert untouched?()
    end

    test "the token is addressed to the report intake", %{conn: conn} do
      conn =
        erase(
          conn,
          %{"username" => "gone"},
          HexServiceTokenFixture.sign(url(~p"/api/hex/reports"))
        )

      assert json_response(conn, 401)
      assert untouched?()
    end

    test "the token names a host the caller chose", %{conn: conn} do
      token = HexServiceTokenFixture.sign("https://evil.example/api/hex/erasures")

      conn = erase(%{conn | host: "evil.example"}, %{"username" => "gone"}, token)

      assert json_response(conn, 401)
      assert untouched?()
    end

    for {label, payload} <- [
          {"there is no username", %{"email" => "gone@example.com"}},
          {"the username is blank", %{"username" => " "}},
          {"the username is not a string", %{"username" => ["gone"]}},
          {"the email is not a string", %{"username" => "gone", "email" => 42}}
        ] do
      test "#{label}", %{conn: conn} do
        conn = erase(conn, unquote(Macro.escape(payload)))

        assert %{"error" => error} = json_response(conn, 400)
        assert is_binary(error)
        assert untouched?()
      end
    end
  end

  test "an erasure token is refused by the report intake", %{conn: conn} do
    conn =
      conn
      |> put_req_header("content-type", "application/json")
      |> put_req_header("authorization", "Bearer #{token()}")
      |> post(~p"/api/hex/reports", %{
        "summary" => "s",
        "description" => "d",
        "package" => "p",
        "reporter" => %{"username" => "reporter"}
      })

    assert json_response(conn, 401)
  end
end
