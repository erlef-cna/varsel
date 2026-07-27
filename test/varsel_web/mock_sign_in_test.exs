# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.MockSignInTest do
  @moduledoc """
  The dev-only provider that offers a role instead of asking a real service.

  It is an ordinary strategy, so what is worth testing is that it behaves like
  one: it appears on the sign-in page, it registers through the same action
  every provider does, and the account it makes carries a normal identity row.
  """

  use VarselWeb.ConnCase, async: false

  alias Varsel.Accounts.User

  require Ash.Query

  defp mock_user(name) do
    User
    |> Ash.Query.filter(name == ^name)
    |> Ash.Query.load([:identities])
    |> Ash.read_one!(authorize?: false)
  end

  # The role is known before the provider is contacted — there is no provider —
  # so the sign-in page offers each one directly rather than a button leading
  # to a page of buttons.
  test "offers each role on the sign-in page", %{conn: conn} do
    html = conn |> get(~p"/sign-in") |> html_response(200)

    for label <- ["Sign in as POC", "Sign in as Supporter", "Sign in as No role"],
        do: assert(html =~ label)

    for uid <- ~w(poc supporter none), do: assert(html =~ "role=#{uid}")
  end

  test "signs in as the chosen role, with an ordinary identity", %{conn: conn} do
    get(conn, "/auth/user/mock/callback?role=poc")

    user = mock_user("Mock POC")

    assert user.role == :poc
    assert Enum.map(user.identities, &to_string(&1.strategy)) == ["mock"]
    assert Enum.map(user.identities, &to_string(&1.uid)) == ["poc"]
  end

  # The identity row is what makes this work: before, a synthetic address and a
  # partial index on the name were needed to find the same account again.
  test "signing in again reuses the account", %{conn: conn} do
    get(conn, "/auth/user/mock/callback?role=supporter")
    first = mock_user("Mock Supporter")

    get(conn, "/auth/user/mock/callback?role=supporter")
    again = mock_user("Mock Supporter")

    assert again.id == first.id
    assert length(again.identities) == 1
  end

  # Its role is set on the way in and not re-forced afterwards, so a change
  # made in the console survives the next sign-in — as it would for GitHub.
  test "does not put back a role the console has changed", %{conn: conn} do
    get(conn, "/auth/user/mock/callback?role=poc")
    user = mock_user("Mock POC")

    Ash.update!(user, %{role: :supporter}, action: :set_role, authorize?: false)

    get(conn, "/auth/user/mock/callback?role=poc")

    assert mock_user("Mock POC").role == :supporter
  end

  test "refuses a role it does not offer", %{conn: conn} do
    conn = get(conn, "/auth/user/mock/callback?role=admin")

    assert conn.status == 302
    assert redirected_to(conn) == "/sign-in"
  end
end
