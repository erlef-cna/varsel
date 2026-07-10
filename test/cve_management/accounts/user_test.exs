# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts.UserTest do
  use CveManagement.DataCase, async: false

  alias CveManagement.Accounts
  alias CveManagement.Accounts.User

  defp register_user(handle \\ nil) do
    handle = handle || "user#{System.unique_integer([:positive])}"

    Ash.create!(
      User,
      %{
        user_info: %{
          "sub" => System.unique_integer([:positive]),
          "preferred_username" => handle,
          "name" => "Test User",
          "email" => "#{handle}@example.com"
        },
        oauth_tokens: %{"access_token" => "gho_secret_token"}
      },
      action: :register_with_github,
      authorize?: false
    )
  end

  describe "first-user auto-POC" do
    test "the very first user to register becomes a POC" do
      first = register_user()
      assert first.role == :poc
    end

    test "subsequent users have no role" do
      register_user()
      second = register_user()
      assert second.role == nil
    end
  end

  describe ":set_role authorization" do
    test "a POC can change another user's role" do
      poc = register_user()
      other = register_user()

      updated = Accounts.set_user_role!(other, :supporter, actor: poc)
      assert updated.role == :supporter
    end

    test "a non-POC cannot change roles" do
      register_user()
      supporter = register_user()
      target = register_user()

      assert {:error, %Ash.Error.Forbidden{}} =
               Accounts.set_user_role(target, :poc, actor: supporter)
    end
  end

  describe "self-promotion is not possible via :update" do
    test "update does not accept role" do
      register_user()
      user = register_user()

      assert {:error, %Ash.Error.Invalid{}} =
               Ash.update(user, %{role: :poc}, action: :update, actor: user)
    end
  end

  describe "list authorization" do
    test "a POC sees all users" do
      poc = register_user()
      register_user()
      register_user()

      assert length(Accounts.list_users!(actor: poc)) == 3
    end

    test "a non-POC sees only themselves" do
      register_user()
      supporter = register_user()

      assert [only] = Accounts.list_users!(actor: supporter)
      assert only.id == supporter.id
    end
  end
end
