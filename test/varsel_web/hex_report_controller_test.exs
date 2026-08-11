# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.HexReportControllerTest do
  use VarselWeb.ConnCase, async: false

  alias Varsel.CVE
  alias Varsel.Fixtures

  @audience "http://localhost:4002/api/hex/reports"

  @signing_key %{
    "crv" => "P-256",
    "d" => "qgBTDHU-tA41X5luD1wc3vjM40y03pudRLsRVGHsWZA",
    "kty" => "EC",
    "x" => "4pRM_ZlHTfTHVvAIxDEBraNmq06ojzDzL2MIHUzkqLk",
    "y" => "5HMC6Ycg9OjJGFbFs46n8rCTxB6VyGWcsLR3bnNWEtU"
  }

  # The payload hexpm/hexpm#1823 posts, from its own client test.
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

  defp token(claims \\ %{}) do
    now = System.system_time(:second)

    claims =
      Enum.into(claims, %{
        "aud" => @audience,
        "exp" => now + 60,
        "iat" => now,
        "iss" => "hexpm",
        "jti" => Ash.UUID.generate(),
        "nbf" => now - 5,
        "sub" => "hexpm"
      })

    {_meta, token} =
      @signing_key
      |> JOSE.JWK.from_map()
      |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => "hexpm-test"}, claims)
      |> JOSE.JWS.compact()

    token
  end

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
      assert URI.new!(url).host == URI.new!(@audience).host
      assert URI.new!(sign_in_url).host == URI.new!(@audience).host
      assert sign_in_url =~ "hex"
      assert is_binary(id)
    end

    test "keeps the payload and names its source", %{conn: conn} do
      poc = Fixtures.register_user("hex_intake_poc", :poc)
      conn = submit(conn, payload(), token())
      %{"id" => id} = json_response(conn, 201)

      report = CVE.get_vulnerability_report!(id, actor: poc)

      assert report.source == :hex
      assert report.summary == "Unsafe parsing"
      assert report.report_json["package"] == "reported_package"
      assert report.reporter_id == nil
    end

    test "records the reporter and the maintainers", %{conn: conn} do
      poc = Fixtures.register_user("hex_participants_poc", :poc)
      conn = submit(conn, payload(), token())
      %{"id" => id} = json_response(conn, 201)

      participants =
        id
        |> CVE.get_vulnerability_report!(actor: poc, load: [:participants])
        |> Map.fetch!(:participants)

      assert [maintainer] = Enum.filter(participants, &(&1.role == :maintainer))
      assert [reporter] = Enum.filter(participants, &(&1.role == :reporter))
      assert to_string(maintainer.username) == "maintainer"
      assert to_string(reporter.username) == "reporter"
      assert reporter.email == "reporter@example.com"
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
      assert CVE.list_vulnerability_reports!(authorize?: false) == []
    end

    test "the token is signed by someone else", %{conn: conn} do
      other = JOSE.JWK.generate_key({:ec, :secp256r1})
      {_type, key} = JOSE.JWK.to_map(other)

      {_meta, forged} =
        key
        |> JOSE.JWK.from_map()
        |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => "hexpm-test"}, %{
          "aud" => @audience,
          "exp" => System.system_time(:second) + 60,
          "iss" => "hexpm",
          "jti" => Ash.UUID.generate(),
          "sub" => "hexpm"
        })
        |> JOSE.JWS.compact()

      conn = submit(conn, payload(), forged)

      assert json_response(conn, 401)
      assert CVE.list_vulnerability_reports!(authorize?: false) == []
    end

    test "the same token is replayed", %{conn: conn} do
      token = token()

      assert conn |> submit(payload(), token) |> json_response(201)
      assert build_conn() |> submit(payload(), token) |> json_response(401)
    end

    test "the payload is missing a required field", %{conn: conn} do
      conn = submit(conn, Map.delete(payload(), "package"), token())

      assert json_response(conn, 400)
      assert CVE.list_vulnerability_reports!(authorize?: false) == []
    end

    test "a named person has no username to match on", %{conn: conn} do
      payload = payload(%{"reporter" => %{"name" => "Reporter", "email" => "r@example.com"}})
      conn = submit(conn, payload, token())

      assert json_response(conn, 400)
    end
  end
end
