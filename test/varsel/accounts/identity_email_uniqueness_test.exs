# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.IdentityEmailUniquenessTest do
  @moduledoc """
  One address belongs to one account, enforced in the database so two
  concurrent OAuth callbacks cannot both slip past a read-then-write check.
  """

  use Varsel.DataCase, async: true

  import Varsel.Fixtures

  alias Ash.Error.Unknown
  alias Varsel.Accounts.UserIdentity

  defp link_identity(user, strategy, uid, email) do
    Ash.create!(
      UserIdentity,
      %{
        user_id: user.id,
        strategy: strategy,
        user_info: %{"sub" => uid, "preferred_username" => uid, "email" => email},
        oauth_tokens: %{"access_token" => "token"}
      },
      action: :upsert,
      authorize?: false
    )
  end

  test "one user may hold the same address on several providers" do
    user = register_user("alice")

    link_identity(user, "hex", "uniqueness_alice_hex", to_string(user.notification_email))

    strategies =
      user
      |> Ash.load!([:identities], authorize?: false)
      |> Map.fetch!(:identities)
      |> Enum.map(&to_string(&1.strategy))
      |> Enum.sort()

    assert strategies == ["github", "hex"]
  end

  test "a second account cannot claim an address another already reported" do
    alice = register_user("alice")
    intruder = register_user("intruder")

    assert_raise Unknown, ~r/one_account_per_email/, fn ->
      link_identity(intruder, "hex", "intruder_hex", to_string(alice.notification_email))
    end
  end

  test "capitalising the address differently does not evade that" do
    alice = register_user("alice")
    intruder = register_user("intruder")
    shouted = alice.notification_email |> to_string() |> String.upcase()

    assert_raise Unknown, ~r/one_account_per_email/, fn ->
      link_identity(intruder, "hex", "intruder_hex", shouted)
    end
  end

  test "accounts whose providers reported no address do not collide" do
    one = register_user("one")
    two = register_user("two")

    link_identity(one, "hex", "one_hex", nil)
    link_identity(two, "hex", "two_hex", nil)

    for user <- [one, two] do
      assert user
             |> Ash.load!([:identities], authorize?: false)
             |> Map.fetch!(:identities)
             |> length() == 2
    end
  end

  test "an address is matched case-insensitively when read back" do
    user = register_user("alice")
    address = to_string(user.notification_email)

    link_identity(user, "hex", "uniqueness_alice_hex", String.upcase(address))

    emails =
      user
      |> Ash.load!([:identities], authorize?: false)
      |> Map.fetch!(:identities)
      |> Enum.filter(&(to_string(&1.strategy) == "hex"))
      |> Enum.map(& &1.email)

    assert Enum.any?(emails, &(Ash.CiString.compare(&1, address) == :eq))
  end
end
