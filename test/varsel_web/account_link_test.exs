# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountLinkTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Accounts.User
  alias VarselWeb.AccountLinkController

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  # Signed in as `user`, mid-link toward `from` — the state the OAuth callback
  # leaves behind. The marker goes in with the session, not after: a second
  # `init_test_session` would reset the token `store_in_session/2` just wrote.
  defp linking_from(conn, user, from) do
    conn
    |> init_test_session(%{AccountLinkController.session_key() => from.id})
    |> AuthPlug.store_in_session(user)
  end

  describe "starting a link" do
    test "remembers the account it was started from and hands off to the provider", %{conn: conn} do
      user = register_user("alice")

      conn = conn |> log_in(user) |> get(~p"/settings/account/link/start/hex")

      assert redirected_to(conn) == "/auth/user/hex"
      assert get_session(conn, AccountLinkController.session_key()) == user.id
    end

    test "an anonymous visitor is sent to sign in", %{conn: conn} do
      conn = get(conn, ~p"/settings/account/link/start/hex")

      assert redirected_to(conn) == "/sign-in"
    end
  end

  describe "the confirmation page" do
    test "names both accounts", %{conn: conn} do
      keep = register_user("keep")
      other = register_user("other")

      html =
        conn
        |> linking_from(other, keep)
        |> get(~p"/settings/account/link/confirm")
        |> html_response(200)

      assert html =~ "keep name"
      assert html =~ "other name"
    end

    test "goes back to the settings page when no link is in progress", %{conn: conn} do
      user = register_user("alice")

      conn = conn |> log_in(user) |> get(~p"/settings/account/link/confirm")

      assert redirected_to(conn) == "/settings/account"
    end
  end

  describe "confirming" do
    test "merges the signed-in account into the one the link started from", %{conn: conn} do
      keep = register_user("keep")
      other = register_user("other")

      conn = conn |> linking_from(other, keep) |> post(~p"/settings/account/link/confirm")

      assert redirected_to(conn) == "/settings/account"
      assert Ash.get!(User, other.id, authorize?: false).merged_into_id == keep.id

      # The provider that was just linked now signs the surviving account in.
      identities =
        keep
        |> Ash.load!([:identities], authorize?: false)
        |> Map.fetch!(:identities)

      assert length(identities) == 2
    end

    test "leaves the session on the surviving account", %{conn: conn} do
      keep = register_user("keep")
      other = register_user("other")

      conn = conn |> linking_from(other, keep) |> post(~p"/settings/account/link/confirm")

      refute get_session(conn, AccountLinkController.session_key())
      assert conn.assigns.current_user.id == keep.id
    end
  end

  describe "declining" do
    test "keeps both accounts and stays signed in as the new one", %{conn: conn} do
      keep = register_user("keep")
      other = register_user("other")

      conn = conn |> linking_from(other, keep) |> post(~p"/settings/account/link/decline")

      assert redirected_to(conn) == "/settings/account"
      refute get_session(conn, AccountLinkController.session_key())

      # Nothing was merged: both accounts stand, each with its own provider.
      assert Ash.get!(User, other.id, authorize?: false).merged_into_id == nil
      assert Ash.get!(User, keep.id, authorize?: false).merged_into_id == nil
    end
  end
end
