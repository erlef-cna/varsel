# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountLinkController do
  @moduledoc """
  Starts linking a second provider to the account already signed in.

  All this does is remember which account asked before handing off to the
  provider. The linking itself happens where the sign-in does — see
  `VarselWeb.Plugs.OauthLinking`, which carries the marker into the register
  action, and `Varsel.Accounts.User.Changes.ResolveOauthIdentity`, which
  attaches the new provider to that account rather than registering a second.
  """

  use VarselWeb, :controller

  alias VarselWeb.Plugs.OauthLinking

  @doc """
  Remembers the current account, then sends the browser to the provider.
  """
  def start(conn, %{"strategy" => strategy}) do
    conn
    |> put_session(OauthLinking.session_key(), conn.assigns.current_user.id)
    |> redirect(to: "/auth/user/#{strategy}")
  end
end
