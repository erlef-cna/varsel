# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.RepositoriesTest do
  use ExUnit.Case, async: false

  alias Varsel.GitHub.Repositories
  alias Varsel.Test.GitHubApi

  test "admin? reads the caller's permissions on the repository" do
    GitHubApi.stub(fn conn ->
      assert conn.path_info == ["repos", "acme", "acme_lib"]
      assert {"authorization", "Bearer gho_x"} in conn.req_headers

      Req.Test.json(conn, %{
        "full_name" => "acme/acme_lib",
        "permissions" => %{"admin" => true, "push" => true, "pull" => true}
      })
    end)

    assert Repositories.admin?("acme", "acme_lib", token: "gho_x") == {:ok, true}
  end

  test "a repository the caller does not administer answers false" do
    GitHubApi.stub(fn conn ->
      Req.Test.json(conn, %{"permissions" => %{"admin" => false, "push" => false, "pull" => true}})
    end)

    assert Repositories.admin?("acme", "acme_lib", token: "gho_x") == {:ok, false}
  end

  test "a repository answered without permissions is not administered" do
    GitHubApi.stub(&Req.Test.json(&1, %{"full_name" => "acme/acme_lib"}))

    assert Repositories.admin?("acme", "acme_lib", token: "gho_x") == {:ok, false}
  end

  test "a repository GitHub does not show the caller is not found" do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, "{}"))

    assert Repositories.admin?("acme", "private", token: "gho_x") == :not_found
  end

  test "a token GitHub no longer accepts is unauthorized" do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 401, "{}"))

    assert Repositories.admin?("acme", "acme_lib", token: "gho_revoked") ==
             {:error, :unauthorized}
  end

  test "a refused read is an error" do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 403, "{}"))

    assert {:error, {:http, 403, _body}} = Repositories.admin?("acme", "acme_lib", token: "gho_x")
  end
end
