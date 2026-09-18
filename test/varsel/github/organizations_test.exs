# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.OrganizationsTest do
  use ExUnit.Case, async: false

  alias Varsel.GitHub.Organizations
  alias Varsel.Test.GitHubApi

  test "owners lists the organization's admins by login" do
    GitHubApi.stub(fn conn ->
      assert conn.path_info == ["orgs", "acme", "members"]
      assert conn.query_params["role"] == "admin"
      assert {"authorization", "Bearer gho_x"} in conn.req_headers
      Req.Test.json(conn, [%{"login" => "alice"}, %{"login" => "bob"}])
    end)

    assert Organizations.owners("acme", token: "gho_x") == {:ok, ["alice", "bob"]}
  end

  test "team members are listed by login" do
    GitHubApi.stub(fn conn ->
      assert conn.path_info == ["orgs", "acme", "teams", "security", "members"]
      Req.Test.json(conn, [%{"login" => "carol"}])
    end)

    assert Organizations.team_members("acme", "security", token: "gho_x") == {:ok, ["carol"]}
  end

  test "an account that is no organization is not found" do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, "{}"))

    assert Organizations.owners("alice", token: "gho_x") == :not_found
  end

  test "a token GitHub no longer accepts is unauthorized" do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 401, "{}"))

    assert Organizations.owners("acme", token: "gho_revoked") == {:error, :unauthorized}
  end

  test "a refused listing is an error" do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 403, "{}"))

    assert {:error, {:http, 403, _body}} =
             Organizations.team_members("acme", "security", token: "gho_x")
  end
end
