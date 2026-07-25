# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

if Application.compile_env(:varsel, :mock_login_enabled?, false) do
  defmodule VarselWeb.MockAuthController do
    @moduledoc """
    Signs in a dummy user without going through GitHub OAuth, so local
    development does not need a configured OAuth app.

    Only compiled when `:mock_login_enabled?` is set (dev only).
    """

    use VarselWeb, :controller

    alias AshAuthentication.Plug.Helpers
    alias Varsel.Accounts

    @roles %{"poc" => :poc, "supporter" => :supporter, "none" => nil}

    def create(conn, %{"role" => role}) when is_map_key(@roles, role) do
      # The sign-in itself runs without an actor (there is none yet), which
      # leaves the returned record's non-public fields redacted by the field
      # policies. Re-reading with the new user as its own actor unredacts them
      # so the nav can see the role it just signed in as.
      signed_in = Accounts.mock_sign_in_user!(%{role: @roles[role]}, authorize?: true)

      # `reload!` returns a fresh struct without the sign-in metadata, so carry
      # the token over — `store_in_session/2` reads it from there.
      user =
        signed_in
        |> Ash.reload!(actor: signed_in)
        |> Ash.Resource.put_metadata(:token, signed_in.__metadata__.token)

      conn
      |> Helpers.store_in_session(user)
      |> assign(:current_user, user)
      |> put_flash(:info, "Signed in as #{user.name}")
      |> redirect(to: ~p"/")
    end
  end
end
