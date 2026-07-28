# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.OauthLinking do
  @moduledoc """
  Carries "this sign-in is a link, to that account" from the session into the
  action the OAuth callback runs.

  The callback registers whoever comes back from the provider and has no idea
  a link was intended; the only thing that knows is the session, written by
  the Link button before the handoff. `AshAuthentication.Strategy.OAuth2.Plug`
  passes the conn's Ash context into the register action, so putting it there
  is enough for `Varsel.Accounts.User.Changes.ResolveOauthIdentity` to see it.

  The account is named by id rather than taken from `current_user` so that an
  expired session cannot quietly turn a link into a fresh registration under
  someone else's provider.
  """
  @behaviour Plug

  import Plug.Conn, only: [get_session: 2]

  @session_key :linking_from_user_id

  @doc "The session key naming the account a link was started from."
  @spec session_key() :: atom()
  def session_key, do: @session_key

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    case get_session(conn, @session_key) do
      nil ->
        conn

      user_id ->
        Ash.PlugHelpers.update_context(conn, &Map.put(&1 || %{}, :linking_user_id, user_id))
    end
  end
end
