# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.SignOutTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  alias AshAuthentication.Phoenix.Controller, as: AuthPhoenixController
  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Phoenix.Socket.Broadcast

  defp purpose(jti) do
    case Varsel.Repo.query!("SELECT purpose FROM tokens WHERE jti = $1", [jti]) do
      %{rows: [[purpose]]} -> purpose
      %{rows: []} -> nil
    end
  end

  # Clearing the cookie only makes the browser forget the token. Left valid, it
  # would keep authenticating anyone holding a copy, and keep showing up as a
  # live session on the account page.
  test "revokes the token, not just the cookie", %{conn: conn} do
    user = register_user("alice")
    {:ok, _token, claims} = AshAuthentication.Jwt.token_for_user(user, %{})
    jti = claims["jti"]

    assert purpose(jti) == "user"

    conn =
      conn
      |> init_test_session(%{"current_session_jti" => jti})
      |> AuthPlug.store_in_session(user)
      |> delete(~p"/sign-out")

    assert redirected_to(conn) == "/"
    assert purpose(jti) == "revocation"
  end

  test "signing out without a recorded session still clears it", %{conn: conn} do
    user = register_user("alice")

    conn =
      conn |> init_test_session(%{}) |> AuthPlug.store_in_session(user) |> delete(~p"/sign-out")

    assert redirected_to(conn) == "/"
    assert get_session(conn, "user") == nil
  end

  test "an anonymous sign-out is harmless", %{conn: conn} do
    conn = conn |> init_test_session(%{}) |> delete(~p"/sign-out")

    assert redirected_to(conn) == "/"
  end

  # Revoking stops the token authenticating afresh, which a LiveView only does
  # when it remounts — until then it keeps acting as the actor it mounted with.
  # The disconnect broadcast is what closes that window.
  describe "live socket disconnect" do
    test "revoking a session broadcasts a disconnect to its socket", %{conn: conn} do
      user = register_user("alice")
      {:ok, _token, claims} = AshAuthentication.Jwt.token_for_user(user, %{})
      jti = claims["jti"]

      VarselWeb.Endpoint.subscribe("users_sessions:#{jti}")

      conn
      |> init_test_session(%{"current_session_jti" => jti})
      |> AuthPlug.store_in_session(user)
      |> delete(~p"/sign-out")

      assert_receive %Broadcast{
        event: "disconnect",
        topic: "users_sessions:" <> ^jti
      }
    end

    test "signing in records the socket id the broadcast targets", %{conn: conn} do
      user = register_user("alice")
      {:ok, token, claims} = AshAuthentication.Jwt.token_for_user(user, %{})

      conn =
        conn
        |> Phoenix.ConnTest.bypass_through(VarselWeb.Router, :browser)
        |> get("/")
        |> AuthPhoenixController.set_live_socket_id(token)

      assert get_session(conn, :live_socket_id) == "users_sessions:#{claims["jti"]}"
    end

    test "deleting an account disconnects its sockets", %{conn: _conn} do
      user = register_user("alice")
      {:ok, _token, claims} = AshAuthentication.Jwt.token_for_user(user, %{})
      jti = claims["jti"]

      VarselWeb.Endpoint.subscribe("users_sessions:#{jti}")

      Ash.destroy!(user, actor: user)

      assert_receive %Broadcast{
        event: "disconnect",
        topic: "users_sessions:" <> ^jti
      }
    end
  end
end
