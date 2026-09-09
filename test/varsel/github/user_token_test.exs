# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserTokenTest do
  use Varsel.DataCase, async: false

  import Varsel.Fixtures, only: [sign_in_with_github: 2, sign_in_with_hex: 2]

  alias Varsel.GitHub.UserToken

  describe "fetch/1" do
    test "hands out the token the GitHub sign-in stored" do
      user = sign_in_with_github("octo", System.unique_integer([:positive]))

      assert UserToken.fetch(user) == {:ok, "gho_token"}
    end

    test "an account without a GitHub identity has no token" do
      user = sign_in_with_hex("hexonly", System.unique_integer([:positive]))

      assert UserToken.fetch(user) == {:error, :no_github_identity}
    end
  end

  describe "linked?/1" do
    test "is whether the account has a GitHub identity" do
      assert UserToken.linked?(sign_in_with_github("octo", System.unique_integer([:positive])))
      refute UserToken.linked?(sign_in_with_hex("hexonly", System.unique_integer([:positive])))
      refute UserToken.linked?(nil)
    end
  end

  describe "message/1" do
    test "states what the action needs" do
      assert UserToken.message(:no_github_identity) == "needs your GitHub account linked"
      assert UserToken.message(:unauthorized) == "needs you to sign in with GitHub again"
    end
  end
end
