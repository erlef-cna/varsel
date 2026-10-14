# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserInstallationTest do
  use Varsel.DataCase, async: true

  import Varsel.Fixtures

  alias Varsel.GitHub
  alias Varsel.GitHub.Client
  alias Varsel.GitHub.UserInstallation
  alias Varsel.Test.GitHubApp

  defp unique(handle), do: "#{handle}#{System.unique_integer([:positive])}"

  defp ids(rows), do: rows |> Enum.map(& &1.installation_id) |> Enum.sort()

  test "asks GitHub with the actor's own token and answers from the cache after" do
    user =
      sign_in_with_github(unique("jdoe"), System.unique_integer([:positive]), %{
        "access_token" => "gho_jdoe"
      })

    test_pid = self()

    Req.Test.stub(Client, fn conn ->
      send(test_pid, {:github, conn.method, conn.request_path})
      assert conn.method == "GET"
      assert conn.request_path == "/user/installations"
      assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_jdoe"]
      Req.Test.json(conn, %{"installations" => [%{"id" => 7}, %{"id" => 8}]})
    end)

    assert {:ok, rows} = GitHub.user_installations(actor: user)
    assert ids(rows) == [7, 8]
    assert_received {:github, "GET", "/user/installations"}

    assert {:ok, rows} = GitHub.user_installations(actor: user)
    assert ids(rows) == [7, 8]
    refute_received {:github, _method, _path}
  end

  test "replaces the actor's rows once they are ten minutes old" do
    user =
      sign_in_with_github(unique("jdoe"), System.unique_integer([:positive]), %{
        "access_token" => "gho_jdoe"
      })

    GitHubApp.seed_user_installations(user, [7, 9], fetched_at: DateTime.shift(DateTime.utc_now(), minute: -11))

    Req.Test.stub(Client, fn conn ->
      assert conn.request_path == "/user/installations"
      Req.Test.json(conn, %{"installations" => [%{"id" => 8}]})
    end)

    assert {:ok, rows} = GitHub.user_installations(actor: user)
    assert ids(rows) == [8]
    assert user |> then(&Ash.read!(UserInstallation, actor: &1)) |> ids() == [8]
  end

  test "returns only the actor's own rows" do
    jdoe = register_user(unique("jdoe"))
    other = register_user(unique("other"))
    GitHubApp.seed_user_installations(jdoe, [7])
    GitHubApp.seed_user_installations(other, [8])
    Req.Test.stub(Client, fn _conn -> flunk("a seeded reach reached GitHub") end)

    assert {:ok, [%{installation_id: 7}]} = GitHub.user_installations(actor: jdoe)
    assert {:ok, [%{installation_id: 8}]} = GitHub.user_installations(actor: other)
    assert jdoe |> then(&Ash.read!(UserInstallation, actor: &1)) |> ids() == [7]
  end

  test "is empty without a request for an actor without a GitHub identity" do
    user = sign_in_with_hex(unique("hexonly"), System.unique_integer([:positive]))
    Req.Test.stub(Client, fn _conn -> flunk("an unlinked actor reached GitHub") end)

    assert GitHub.user_installations(actor: user) == {:ok, []}
  end

  test "is refused to an anonymous caller" do
    assert {:error, %Ash.Error.Forbidden{}} = GitHub.user_installations(actor: nil)
    refute GitHub.can_user_installations?(nil)
  end
end
