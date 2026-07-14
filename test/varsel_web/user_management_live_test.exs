# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UserManagementLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Accounts.User

  defp register(handle, role \\ nil) do
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

  test "a POC sees all users listed", %{conn: conn} do
    poc = register("poc", :poc)
    register("alice")
    register("bob")

    {:ok, _lv, html} = conn |> log_in(poc) |> live(~p"/users")

    assert html =~ "User Management"
    assert html =~ "alice@example.com"
    assert html =~ "bob@example.com"
    assert html =~ "@alice"
  end

  test "a POC can change a user's role", %{conn: conn} do
    poc = register("poc", :poc)
    alice = register("alice")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/users")

    lv
    |> form("#role-#{alice.id}", %{"role" => "supporter"})
    |> render_change()

    updated = Ash.get!(User, alice.id, authorize?: false)
    assert updated.role == :supporter
  end

  test "the list updates live when another session changes a role", %{conn: conn} do
    poc = register("poc", :poc)
    alice = register("alice")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/users")

    role_option = ~s(form#role-#{alice.id} option[value="supporter"][selected])
    refute has_element?(lv, role_option)

    # Simulate another POC (or process) changing alice's role out-of-band.
    # The pub_sub notification should drive a refetch in the open LiveView.
    Ash.update!(alice, %{role: :supporter}, action: :set_role, authorize?: false)

    assert has_element?(lv, role_option)
  end

  test "a non-POC is redirected away", %{conn: conn} do
    register("first", :poc)
    supporter = register("supporter", :supporter)

    assert {:error, {:redirect, %{to: "/"}}} =
             conn |> log_in(supporter) |> live(~p"/users")
  end

  test "an anonymous visitor is redirected to sign in", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/sign-in"}}} = live(conn, ~p"/users")
  end
end
