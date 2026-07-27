# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GraphqlSocket do
  @moduledoc """
  Websocket transport for GraphQL, carrying the same login requirement as
  `/gql`.

  A socket has no `conn`, so the `:graphql` pipeline's plugs cannot run here.
  This module resolves an actor from the same three credentials they accept —
  an `eefcna_` API key, an AshAuthentication session, or an OAuth 2.1 access
  token carrying the `gql` scope — and refuses the handshake when none of them
  identifies a user. Policies alone would keep an actor-less socket to public
  data, but `/gql` requires a login even for that, and a second GraphQL
  entrance that did not would undo the decision.

  Credentials arrive in the connect params rather than a header, since browsers
  cannot set headers on a websocket handshake. The session cookie is read too,
  so a signed-in browser needs no token.
  """

  use Phoenix.Socket

  use Absinthe.Phoenix.Socket,
    schema: VarselWeb.GraphqlSchema

  alias Absinthe.Phoenix.Socket, as: AbsintheSocket
  alias AshAuthentication.Info
  alias AshAuthentication.Oauth2Server.Jwt, as: Oauth2Jwt
  alias AshAuthentication.Plug.Helpers
  alias AshAuthentication.Strategy
  alias Varsel.Accounts
  alias Varsel.Accounts.User

  @api_key_prefix "eefcna_"
  @scope "gql"

  @impl Phoenix.Socket
  def connect(params, socket, connect_info) do
    case actor(params, connect_info) do
      {:ok, user} ->
        {:ok,
         socket
         |> assign(:current_user, user)
         |> AbsintheSocket.put_options(context: %{actor: user})}

      :error ->
        # Phoenix answers the handshake with 403 and no socket is established.
        :error
    end
  end

  # Sockets are not resumable and carry no per-user broadcast, so there is
  # nothing to disconnect by id.
  @impl Phoenix.Socket
  def id(_socket), do: nil

  # The three credentials `/gql` accepts, tried in the same order the pipeline
  # runs them: API key, session JWT, then OAuth token.
  defp actor(params, connect_info) do
    with :error <- api_key(params),
         :error <- session_user(connect_info) do
      oauth_token(params)
    end
  end

  defp api_key(%{"api_key" => @api_key_prefix <> _ = api_key}) do
    strategy = Info.strategy!(User, :api_key)

    case Strategy.action(strategy, :sign_in, %{api_key: api_key}, []) do
      {:ok, user} -> {:ok, user}
      _invalid -> :error
    end
  end

  defp api_key(_no_key), do: :error

  # A signed-in browser. Delegated rather than re-derived: this app requires a
  # stored token to be present, so the session JWT alone is not enough — the
  # token must still exist and be unrevoked, which is what makes signing out
  # (and ending a session from the account page) end it here too.
  defp session_user(%{session: session}) when is_map(session) do
    case Helpers.authenticate_resource_from_session(User, session, :varsel, []) do
      {:ok, user} -> {:ok, user}
      _invalid -> :error
    end
  end

  defp session_user(_no_session), do: :error

  # An OAuth 2.1 access token must carry the `gql` scope, exactly as
  # `VarselWeb.Plugs.OauthBearerAuth` requires on the HTTP surface. The
  # subject is a bare user id here, not an AshAuthentication subject string,
  # so it is looked up the way `BearerPlug` does.
  defp oauth_token(%{"token" => token}) when is_binary(token) do
    with {:ok, claims} <- Oauth2Jwt.verify(Varsel.Oauth2Server, token),
         true <- @scope in scopes(claims),
         %{"sub" => subject} when is_binary(subject) <- claims do
      user_by_id(subject)
    else
      _invalid -> :error
    end
  end

  defp oauth_token(_no_token), do: :error

  # Resolving the token's subject is what establishes the actor, so the read
  # cannot be gated on one — it runs through the same AshAuthentication bypass
  # `BearerPlug` uses.
  defp user_by_id(id) do
    case Accounts.get_user_by_id(id, context: %{private: %{ash_authentication?: true}}) do
      {:ok, user} -> {:ok, user}
      _not_found -> :error
    end
  end

  defp scopes(claims) do
    claims |> Map.get("scope", "") |> String.split(" ", trim: true)
  end
end
