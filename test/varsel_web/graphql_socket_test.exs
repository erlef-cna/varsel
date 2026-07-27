# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GraphqlSocketTest do
  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias AshAuthentication.Jwt, as: SessionJwt
  alias AshAuthentication.Oauth2Server.Jwt
  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias AshAuthentication.TokenResource.Actions, as: TokenActions
  alias Varsel.Accounts.Token
  alias Varsel.Accounts.User
  alias VarselWeb.GraphqlSocket

  defp connect(params, connect_info \\ %{}) do
    GraphqlSocket.connect(params, %Phoenix.Socket{}, connect_info)
  end

  # The session the browser would carry, in the shape connect_info hands over.
  defp session_for(user) do
    %Plug.Conn{}
    |> Plug.Test.init_test_session(%{})
    |> AuthPlug.store_in_session(user)
    |> Map.get(:private)
    |> Map.get(:plug_session)
  end

  test "a connection with no credential is refused" do
    assert :error = connect(%{})
  end

  test "an invalid API key is refused" do
    assert :error = connect(%{"api_key" => "eefcna_nonsense"})
  end

  test "a bearer value that is not one of our credentials is refused" do
    assert :error = connect(%{"token" => "not-a-token"})
  end

  test "a valid API key authenticates the socket" do
    user = register_user("alice", :poc)
    {_api_key, plaintext} = create_api_key(user)

    assert {:ok, socket} = connect(%{"api_key" => plaintext})
    assert socket.assigns.current_user.id == user.id
  end

  test "the actor reaches Absinthe, so policies see it" do
    user = register_user("alice", :poc)
    {_api_key, plaintext} = create_api_key(user)

    assert {:ok, socket} = connect(%{"api_key" => plaintext})
    assert %{opts: opts} = socket.assigns.absinthe
    assert opts[:context][:actor].id == user.id
  end

  test "a signed-in browser session authenticates the socket" do
    user = register_user("alice")

    assert {:ok, socket} = connect(%{}, %{session: session_for(user)})
    assert socket.assigns.current_user.id == user.id
  end

  test "an OAuth token carrying the gql scope authenticates the socket" do
    user = register_user("alice", :poc)

    {:ok, token, _claims} =
      Jwt.mint(Varsel.Oauth2Server,
        sub: user.id,
        client_id: "test-client",
        scope: "gql"
      )

    assert {:ok, socket} = connect(%{"token" => token})
    assert socket.assigns.current_user.id == user.id
  end

  # The same rule the HTTP surface enforces: a token minted for MCP is not a
  # GraphQL credential, even though both surfaces share an audience.
  test "an OAuth token without the gql scope is refused" do
    user = register_user("alice", :poc)

    {:ok, token, _claims} =
      Jwt.mint(Varsel.Oauth2Server,
        sub: user.id,
        client_id: "test-client",
        scope: "mcp"
      )

    assert :error = connect(%{"token" => token})
  end

  # Sign-out revokes the stored token rather than only dropping the cookie, so
  # a copied session must stop working here too.
  test "a revoked session no longer authenticates the socket" do
    user = register_user("alice")
    session = session_for(user)

    assert {:ok, _socket} = connect(%{}, %{session: session})

    {:ok, %{"jti" => jti}, _} = SessionJwt.verify(session["user_token"], User)

    :ok =
      TokenActions.revoke_jti(
        Token,
        jti,
        AshAuthentication.user_to_subject(user),
        store_all_tokens?: true
      )

    assert :error = connect(%{}, %{session: session})
  end
end
