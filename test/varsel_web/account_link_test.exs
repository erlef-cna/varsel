# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountLinkTest do
  @moduledoc """
  Linking a second provider to an account already signed in.

  The link resolves inside the OAuth callback rather than in a page of its
  own: the Link button leaves a marker in the session, and the register action
  attaches the provider to the account it names. These drive the register
  action directly, since the provider half of the round trip cannot be faked.
  """

  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  alias Ash.Resource
  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias AshAuthentication.Strategy.OAuth2
  alias Varsel.Accounts.User
  alias VarselWeb.Plugs.OauthLinking

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  # The register action the OAuth callback runs, set up the way
  # `AshAuthentication.Strategy.OAuth2.Actions.register/3` sets it up.
  # `linking` is the account a link was started from, or nil for an ordinary
  # sign-in.
  defp register_via(strategy_name, uid, email, linking \\ nil) do
    action_name = String.to_existing_atom("register_with_#{strategy_name}")
    action = Resource.Info.action(User, action_name, :create)
    linking_context = if linking, do: %{linking_user_id: linking.id}, else: %{}

    User
    |> Ash.Changeset.new()
    |> Ash.Changeset.set_context(Map.put(linking_context, :private, %{ash_authentication?: true}))
    |> Ash.Changeset.for_create(
      action_name,
      %{
        user_info: %{"sub" => uid, "preferred_username" => uid, "email" => email},
        oauth_tokens: %{"access_token" => "token"}
      },
      authorize?: false,
      upsert?: true,
      upsert_identity: action.upsert_identity
    )
    |> Ash.create()
  end

  # The whole call the OAuth callback makes, not just the action underneath —
  # including the error re-wrapping that only happens at this level.
  defp register_through_callback(strategy_name, uid, email, linking) do
    {:ok, strategy} =
      AshAuthentication.Info.strategy(User, String.to_existing_atom(strategy_name))

    OAuth2.Actions.register(
      strategy,
      %{
        user_info: %{"sub" => uid, "preferred_username" => uid, "email" => email},
        oauth_tokens: %{"access_token" => "token"}
      },
      authorize?: false,
      context: %{linking_user_id: linking.id}
    )
  end

  # A refusal surfaces as `AuthenticationFailed`, whose own message is the
  # generic "Authentication failed" — the reason it carries is what says which
  # refusal it was, and what the sign-in page turns into a sentence.
  defp caused_by_message(error) do
    error
    |> List.wrap()
    |> Enum.flat_map(&(Map.get(&1, :errors) || List.wrap(&1)))
    |> Enum.find_value("", fn
      %{caused_by: %{message: message}} -> message
      _other -> nil
    end)
  end

  defp strategies_of(user) do
    user
    |> Ash.load!([:identities], authorize?: false)
    |> Map.fetch!(:identities)
    |> Enum.map(&to_string(&1.strategy))
    |> Enum.sort()
  end

  describe "starting a link" do
    test "remembers the account it was started from and hands off to the provider", %{conn: conn} do
      user = register_user("alice")

      conn = conn |> log_in(user) |> get(~p"/settings/account/link/start/hex")

      assert redirected_to(conn) == "/auth/user/hex"
      assert get_session(conn, OauthLinking.session_key()) == user.id
    end

    test "an anonymous visitor is sent to sign in", %{conn: conn} do
      conn = get(conn, ~p"/settings/account/link/start/hex")

      assert redirected_to(conn) == "/sign-in"
    end
  end

  describe "a sign-in that is not a link" do
    test "registers a new account when nothing holds the address" do
      assert {:ok, user} = register_via("hex", "newcomer", "newcomer@example.com")

      assert strategies_of(user) == ["hex"]
    end

    test "is refused when an account already holds the address" do
      register_user("alice")

      assert {:error, error} = register_via("hex", "alice_hex", "alice@example.com")
      assert caused_by_message(error) =~ "already exists"
    end
  end

  describe "a sign-in that is a link" do
    test "attaches the provider to the account instead of registering a second" do
      alice = register_user("alice")

      assert {:ok, user} = register_via("hex", "alice_hex", "alice@example.com", alice)

      assert user.id == alice.id
      assert strategies_of(alice) == ["github", "hex"]
    end

    test "attaches even when the provider reports an address nobody holds" do
      alice = register_user("alice")

      assert {:ok, user} = register_via("hex", "alice_hex", "elsewhere@example.com", alice)

      assert user.id == alice.id
      assert strategies_of(alice) == ["github", "hex"]
    end

    test "is refused when that provider account already signs someone else in" do
      alice = register_user("alice")
      {:ok, _bob} = register_via("hex", "bob_hex", "bob@example.com")

      assert {:error, error} = register_via("hex", "bob_hex", "bob@example.com", alice)
      assert caused_by_message(error) =~ "already signs in to a different account"

      # Neither account gained or lost a provider.
      assert strategies_of(alice) == ["github"]
    end

    # The refusal above is only useful if it survives the controller. It goes
    # through `OAuth2.Actions.register/3`, which re-wraps the action's error in
    # another `AuthenticationFailed` — so the reason arrives nested, and a
    # controller matching a fixed depth silently falls back to "Incorrect email
    # or password". Drive the same call the callback makes, wrapping and all.
    test "says why it was refused rather than blaming a password", %{conn: conn} do
      alice = register_user("alice")
      {:ok, _bob} = register_via("hex", "bob_hex", "bob@example.com")
      {:error, error} = register_through_callback("hex", "bob_hex", "bob@example.com", alice)

      conn =
        conn
        |> init_test_session(%{OauthLinking.session_key() => alice.id})
        |> fetch_flash()
        |> VarselWeb.AuthController.failure({:hex, :callback}, error)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "already signs in to a different account"

      # ...and back to where the link was started, not to the sign-in page.
      assert redirected_to(conn) == "/settings/account"
    end

    test "is a no-op when the provider is already this account's" do
      alice = register_user("alice")
      {:ok, _} = register_via("hex", "alice_hex", "alice@example.com", alice)

      assert {:ok, user} = register_via("hex", "alice_hex", "alice@example.com", alice)

      assert user.id == alice.id
      assert strategies_of(alice) == ["github", "hex"]
    end
  end
end
