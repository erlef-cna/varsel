# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GraphqlSocket do
  @moduledoc """
  Websocket transport for GraphQL, carrying the same login requirement as
  `/gql`.

  A socket has no `conn`, so the `:graphql` pipeline's plugs cannot run here.
  This module resolves an actor from an `eefcna_` API key or an OAuth 2.1
  access token carrying the `gql` scope, and refuses the handshake when
  neither identifies a user — the login `/gql` requires holds on both GraphQL
  entrances.

  Credentials arrive in the connect params rather than a header, since browsers
  cannot set headers on a websocket handshake.

  A socket resolves its actor once and keeps it, so it closes when that
  authority is withdrawn — the credential deleted, the role changed, the
  account deleted — or when the credential expires
  (`VarselWeb.SocketDisconnect`).
  """

  use Phoenix.Socket

  use Absinthe.Phoenix.Socket,
    schema: VarselWeb.GraphqlSchema

  alias Absinthe.Phoenix.Socket, as: AbsintheSocket
  alias AshAuthentication.Info
  alias AshAuthentication.Oauth2Server.Jwt, as: Oauth2Jwt
  alias AshAuthentication.Strategy
  alias Varsel.Accounts
  alias Varsel.Accounts.User
  alias VarselWeb.SocketDisconnect

  @api_key_prefix "eefcna_"
  @scope "gql"

  @impl Phoenix.Socket
  def connect(params, socket, _connect_info) do
    case actor(params) do
      {:ok, user, credential} ->
        # `id/1` covers the credential; the user topic covers the authority it
        # carries, so a demotion or a deleted account closes the socket
        # whichever credential opened it. Phoenix stops the transport on a
        # "disconnect" broadcast from any subscription it holds.
        VarselWeb.Endpoint.subscribe(SocketDisconnect.user_topic(user.id))
        schedule_expiry(credential)

        {:ok,
         socket
         |> assign(:current_user, user)
         |> assign(:credential, credential)
         |> AbsintheSocket.put_options(context: %{actor: user})}

      :error ->
        # Phoenix answers the handshake with 403 and no socket is established.
        :error
    end
  end

  # Closes the socket when the credential that opened it expires. The message
  # is the struct a revocation broadcast delivers, which is what the transport
  # stops on.
  defp schedule_expiry({_type, _id, nil}), do: :ok
  defp schedule_expiry({:oauth, nil}), do: :ok
  defp schedule_expiry({:api_key, _id, expires_at}), do: send_disconnect_at(expires_at)
  defp schedule_expiry({:oauth, expires_at}), do: send_disconnect_at(expires_at)

  defp send_disconnect_at(expires_at) do
    remaining = DateTime.diff(expires_at, DateTime.utc_now(), :millisecond)

    Process.send_after(
      self(),
      %Phoenix.Socket.Broadcast{event: "disconnect", topic: "credential_expiry", payload: %{}},
      max(remaining, 0)
    )

    :ok
  end

  # Names the revocable credential that opened the socket, so deleting it
  # closes the socket. An OAuth token is revoked by expiring, which
  # `schedule_expiry/1` handles.
  @impl Phoenix.Socket
  def id(%{assigns: %{credential: {:api_key, api_key_id, _expires_at}}}), do: SocketDisconnect.api_key_topic(api_key_id)

  def id(_oauth_socket), do: nil

  # The two credentials `/gql` accepts, tried in the order the pipeline runs
  # them: API key, then OAuth token.
  defp actor(params) do
    with :error <- api_key(params) do
      oauth_token(params)
    end
  end

  defp api_key(%{"api_key" => @api_key_prefix <> _ = api_key}) do
    strategy = Info.strategy!(User, :api_key)

    case Strategy.action(strategy, :sign_in, %{api_key: api_key}, []) do
      {:ok, %{__metadata__: %{api_key: %{id: id} = key}} = user} ->
        {:ok, user, {:api_key, id, Map.get(key, :expires_at)}}

      _invalid ->
        :error
    end
  end

  defp api_key(_no_key), do: :error

  # An OAuth 2.1 access token must carry the `gql` scope, exactly as
  # `VarselWeb.Plugs.OauthBearerAuth` requires on the HTTP surface. The
  # subject is a bare user id here, not an AshAuthentication subject string,
  # so it is looked up the way `BearerPlug` does.
  defp oauth_token(%{"token" => token}) when is_binary(token) do
    with {:ok, claims} <- Oauth2Jwt.verify(Varsel.Oauth2Server, token),
         true <- @scope in scopes(claims),
         %{"sub" => subject} when is_binary(subject) <- claims,
         {:ok, user} <- user_by_id(subject) do
      {:ok, user, {:oauth, expires_at(claims)}}
    else
      _invalid -> :error
    end
  end

  defp oauth_token(_no_token), do: :error

  defp expires_at(%{"exp" => exp}) when is_integer(exp), do: DateTime.from_unix!(exp)
  defp expires_at(_no_exp), do: nil

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
