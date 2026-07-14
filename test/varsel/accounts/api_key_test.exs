# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.ApiKeyTest do
  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias Varsel.Accounts
  alias Varsel.Accounts.ApiKey
  alias Varsel.Accounts.User

  describe "create" do
    test "returns the plaintext key once, in metadata only" do
      user = register_user("alice")
      {api_key, plaintext} = create_api_key(user)

      assert String.starts_with?(plaintext, "eefcna_")
      assert is_binary(api_key.api_key_hash)
      refute api_key.api_key_hash == plaintext

      reloaded = Ash.get!(ApiKey, api_key.id, authorize?: false)
      refute reloaded.__metadata__[:plaintext_api_key]
    end

    test "anonymous actors cannot create keys" do
      # relate_actor fails before policies even run when there is no actor.
      assert {:error, _error} = Accounts.create_api_key(%{name: "nope"}, actor: nil)
      assert Ash.read!(ApiKey, authorize?: false) == []
    end
  end

  describe "policies" do
    test "users list only their own keys" do
      alice = register_user("alice")
      bob = register_user("bob")
      {alice_key, _plaintext} = create_api_key(alice)
      {_bob_key, _plaintext} = create_api_key(bob)

      assert [%ApiKey{id: id}] = Accounts.list_api_keys!(actor: alice)
      assert id == alice_key.id
    end

    test "users cannot revoke another user's key" do
      alice = register_user("alice")
      bob = register_user("bob")
      {bob_key, _plaintext} = create_api_key(bob)

      assert {:error, _error} = Accounts.revoke_api_key(bob_key, actor: alice)
      assert Ash.get!(ApiKey, bob_key.id, authorize?: false)
    end

    test "users can revoke their own key" do
      alice = register_user("alice")
      {alice_key, _plaintext} = create_api_key(alice)

      assert :ok = Accounts.revoke_api_key(alice_key, actor: alice)
      assert Accounts.list_api_keys!(actor: alice) == []
    end
  end

  describe "sign_in_with_api_key" do
    defp sign_in(plaintext) do
      User
      |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: plaintext})
      |> Ash.read_one(authorize?: false)
    end

    test "a valid key signs in its owner" do
      user = register_user("alice")
      {_api_key, plaintext} = create_api_key(user)

      assert {:ok, %User{} = signed_in} = sign_in(plaintext)
      assert signed_in.id == user.id
      assert signed_in.__metadata__.using_api_key?
    end

    test "an expired key does not sign in" do
      user = register_user("alice")
      expires_at = DateTime.add(DateTime.utc_now(), -1, :day)
      {_api_key, plaintext} = create_api_key(user, %{expires_at: expires_at})

      result = sign_in(plaintext)
      refute match?({:ok, %User{}}, result)
    end

    test "a garbage key does not sign in" do
      register_user("alice")

      result = sign_in("eefcna_definitely_not_a_key")
      refute match?({:ok, %User{}}, result)
    end
  end

  describe "paper trail" do
    test "versions are written but never contain the key hash" do
      user = register_user("alice")
      {api_key, _plaintext} = create_api_key(user)
      :ok = Accounts.revoke_api_key(api_key, actor: user)

      versions = Ash.read!(Varsel.Accounts.ApiKey.Version, authorize?: false)
      assert versions != []

      for version <- versions do
        refute Map.has_key?(version.changes || %{}, "api_key_hash")
      end
    end
  end
end
