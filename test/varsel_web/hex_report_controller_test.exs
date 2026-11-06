# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.HexReportControllerTest do
  use VarselWeb.ConnCase, async: true

  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.HexPm
  alias VarselWeb.HexServiceTokenFixture

  # The case a report opens invites the people it names, which confirms
  # each handle at hex.pm.
  setup do
    Req.Test.stub(HexPm, fn conn ->
      case conn.path_info do
        ["api", "users", username, "contact"] when username in ["reporter", "maintainer"] ->
          Req.Test.json(conn, %{
            "username" => username,
            "name" => username,
            "email" => "#{username}@example.com"
          })

        _unknown ->
          Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    :ok
  end

  # What the plug derives, so the token is addressed where the server listens.
  defp audience, do: url(~p"/api/hex/reports")

  # Copied from hex.pm's own client test, so a drift there shows up here.
  defp payload(overrides \\ %{}) do
    Map.merge(
      %{
        "summary" => "Unsafe parsing",
        "description" => "A crafted document can execute code.",
        "package" => "reported_package",
        "maintainers" => [
          %{
            "name" => "Maintainer",
            "username" => "maintainer",
            "email" => "maintainer@example.com"
          }
        ],
        "reporter" => %{
          "name" => "Reporter",
          "username" => "reporter",
          "email" => "reporter@example.com"
        }
      },
      overrides
    )
  end

  defp token(claims \\ %{}), do: HexServiceTokenFixture.sign(audience(), claims)

  defp submit(conn, payload, token) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer #{token}")
    |> post(~p"/api/hex/reports", payload)
  end

  describe "a report hex.pm forwards" do
    test "is stored and answered the way the sender expects", %{conn: conn} do
      conn = submit(conn, payload(), token())

      assert %{"id" => id, "url" => url, "sign_in_url" => sign_in_url} =
               json_response(conn, 201)

      # The sender refuses a response whose Location disagrees with the body,
      # or whose links point off its configured origin.
      assert [^url] = get_resp_header(conn, "location")
      assert is_binary(id)

      # Both links lead to the case the report opened.
      %{cases: [case_record]} =
        Cases.get_vulnerability_report!(id, authorize?: false, load: [:cases])

      assert url == url(~p"/cases/#{case_record.id}")
      assert sign_in_url == url(~p"/auth/user/hex?#{%{return_to: ~p"/cases/#{case_record.id}"}}")
    end

    test "keeps the payload and names its source", %{conn: conn} do
      poc = Fixtures.register_user("hex_intake_poc", :poc)
      conn = submit(conn, payload(), token())
      %{"id" => id} = json_response(conn, 201)

      report = Cases.get_vulnerability_report!(id, actor: poc)

      assert report.source == :hex
      assert report.summary == "Unsafe parsing"
      assert report.report_json["package"] == "reported_package"
      assert report.report_json["report"] == "A crafted document can execute code."
      assert report.reporter_id == nil
    end

    test "opens a case that invites the reporter and the maintainers", %{conn: conn} do
      poc = Fixtures.register_user("hex_people_poc", :poc)
      conn = submit(conn, payload(), token())
      %{"id" => id} = json_response(conn, 201)

      report = Cases.get_vulnerability_report!(id, actor: poc, load: [:cases])
      assert to_string(report.reporter_username) == "reporter"

      assert [case_record] = report.cases
      invites = Cases.get_case!(case_record.id, actor: poc, load: [:invites]).invites

      assert MapSet.new(invites, &{to_string(&1.username), to_string(&1.email)}) ==
               MapSet.new([
                 {"reporter", "reporter@example.com"},
                 {"maintainer", "maintainer@example.com"}
               ])
    end

    test "is refused as a whole when a named handle is not a hex.pm account", %{conn: conn} do
      payload = payload(%{"maintainers" => [%{"username" => "nobody"}]})
      conn = submit(conn, payload, token())

      assert json_response(conn, 422)
      assert Cases.list_vulnerability_reports!(authorize?: false) == []
    end

    test "is accepted with no maintainers at all", %{conn: conn} do
      conn = submit(conn, payload(%{"maintainers" => []}), token())

      assert %{"id" => _id} = json_response(conn, 201)
    end
  end

  describe "is refused when" do
    test "no token is presented", %{conn: conn} do
      conn = post(conn, ~p"/api/hex/reports", payload())

      assert json_response(conn, 401)
      assert Cases.list_vulnerability_reports!(authorize?: false) == []
    end

    test "the token is signed by someone else", %{conn: conn} do
      other = JOSE.JWK.generate_key({:ec, :secp256r1})
      {_type, key} = JOSE.JWK.to_map(other)

      {_meta, forged} =
        key
        |> JOSE.JWK.from_map()
        |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => "hexpm-test"}, %{
          "aud" => audience(),
          "exp" => System.system_time(:second) + 60,
          "iss" => "hexpm",
          "jti" => Ash.UUID.generate(),
          "sub" => "hexpm"
        })
        |> JOSE.JWS.compact()

      conn = submit(conn, payload(), forged)

      assert json_response(conn, 401)
      assert Cases.list_vulnerability_reports!(authorize?: false) == []
    end

    test "the token names a host the caller chose", %{conn: conn} do
      token = token(%{"aud" => "https://evil.example/api/hex/reports"})

      conn = submit(%{conn | host: "evil.example"}, payload(), token)

      assert json_response(conn, 401)
    end

    test "the same token is replayed", %{conn: conn} do
      token = token()

      assert conn |> submit(payload(), token) |> json_response(201)
      assert build_conn() |> submit(payload(), token) |> json_response(401)
    end

    test "the payload is missing a required field", %{conn: conn} do
      conn = submit(conn, Map.delete(payload(), "package"), token())

      assert json_response(conn, 400)
      assert Cases.list_vulnerability_reports!(authorize?: false) == []
    end

    test "the summary is longer than the column takes", %{conn: conn} do
      conn = submit(conn, payload(%{"summary" => String.duplicate("a", 2_001)}), token())

      assert json_response(conn, 422)
      assert Cases.list_vulnerability_reports!(authorize?: false) == []
    end

    test "the payload is larger than intake allows", %{conn: conn} do
      payload = payload(%{"description" => String.duplicate("a", 300_000)})
      conn = submit(conn, payload, token())

      assert json_response(conn, 422)
      assert Cases.list_vulnerability_reports!(authorize?: false) == []
    end

    test "a named person has no username to match on", %{conn: conn} do
      payload = payload(%{"reporter" => %{"name" => "Reporter", "email" => "r@example.com"}})
      conn = submit(conn, payload, token())

      assert json_response(conn, 400)
    end
  end
end
