# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GraphqlSocketTest do
  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias AshAuthentication.Oauth2Server.Jwt
  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Phoenix.Socket.Broadcast
  alias VarselWeb.GraphqlSocket
  alias VarselWeb.SocketDisconnect

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

  # Authority on every GraphQL entrance comes from a presented credential, so
  # a browser carrying only a session is refused like any other caller.
  test "a signed-in browser session does not authenticate the socket" do
    user = register_user("alice")

    assert :error = connect(%{}, %{session: session_for(user)})
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

  describe "authority ends when the credential does" do
    test "the socket is named after the API key that opened it" do
      user = register_user("alice", :poc)
      {api_key, plaintext} = create_api_key(user)

      assert {:ok, socket} = connect(%{"api_key" => plaintext})
      assert GraphqlSocket.id(socket) == SocketDisconnect.api_key_topic(api_key.id)
    end

    # An OAuth token is bounded by its expiry, which the socket schedules.
    test "an OAuth socket is not named after a credential" do
      user = register_user("alice", :poc)

      {:ok, token, _claims} =
        Jwt.mint(Varsel.Oauth2Server, sub: user.id, client_id: "test-client", scope: "gql")

      assert {:ok, socket} = connect(%{"token" => token})
      assert GraphqlSocket.id(socket) == nil
    end

    test "deleting an API key closes the sockets it opened" do
      user = register_user("alice", :poc)
      {api_key, plaintext} = create_api_key(user)

      VarselWeb.Endpoint.subscribe(SocketDisconnect.api_key_topic(api_key.id))
      assert {:ok, _socket} = connect(%{"api_key" => plaintext})

      Ash.destroy!(api_key, actor: user)

      assert_receive %Broadcast{event: "disconnect"}
    end

    # A socket holds the role it resolved at connect, so a demotion reaches it
    # whichever credential opened it.
    test "a role change closes the user's sockets" do
      user = register_user("alice", :poc)
      {_api_key, plaintext} = create_api_key(user)

      VarselWeb.Endpoint.subscribe(SocketDisconnect.user_topic(user.id))
      assert {:ok, _socket} = connect(%{"api_key" => plaintext})

      Ash.update!(user, %{role: :supporter}, action: :set_role, authorize?: false)

      assert_receive %Broadcast{event: "disconnect"}
    end

    test "deleting the account closes the user's sockets" do
      user = register_user("alice", :poc)
      {_api_key, plaintext} = create_api_key(user)

      VarselWeb.Endpoint.subscribe(SocketDisconnect.user_topic(user.id))
      assert {:ok, _socket} = connect(%{"api_key" => plaintext})

      Ash.destroy!(user, actor: user)

      assert_receive %Broadcast{event: "disconnect"}
    end

    test "an ordinary update leaves open sockets alone" do
      user = register_user("alice", :poc)

      VarselWeb.Endpoint.subscribe(SocketDisconnect.user_topic(user.id))

      Ash.update!(user, %{name: "Alice B."}, action: :update, actor: user)

      refute_receive %Broadcast{event: "disconnect"}
    end

    test "an expiring credential schedules its own disconnect" do
      user = register_user("alice", :poc)

      {api_key, plaintext} =
        create_api_key(user, %{expires_at: DateTime.add(DateTime.utc_now(), 50, :millisecond)})

      assert {:ok, _socket} = connect(%{"api_key" => plaintext})
      assert api_key.expires_at

      # Delivered to the connecting process itself, in the shape the transport
      # stops on.
      assert_receive %Broadcast{event: "disconnect", topic: "credential_expiry"},
                     1_000
    end
  end
end
