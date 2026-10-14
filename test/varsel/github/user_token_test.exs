# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserTokenTest do
  use Varsel.DataCase, async: false

  import ExUnit.CaptureLog

  import Varsel.Fixtures,
    only: [sign_in_with_github: 2, sign_in_with_github: 3, sign_in_with_hex: 2]

  alias Ash.Error.Forbidden
  alias Varsel.Accounts
  alias Varsel.GitHub.UserToken

  describe "fetch/1" do
    test "hands out the token the GitHub sign-in stored" do
      user = sign_in_with_github("octo", System.unique_integer([:positive]))

      assert UserToken.fetch(user) == {:ok, "gho_token"}
    end

    test "a returning sign-in replaces the stored tokens" do
      sub = System.unique_integer([:positive])

      sign_in_with_github("octo", sub, %{
        "access_token" => "ghu_first",
        "refresh_token" => "ghr_first"
      })

      user =
        sign_in_with_github("octo", sub, %{
          "access_token" => "ghu_second",
          "refresh_token" => "ghr_second"
        })

      assert UserToken.fetch(user) == {:ok, "ghu_second"}
      assert github_identity(user).refresh_token == "ghr_second"
    end

    test "an account without a GitHub identity has no token" do
      user = sign_in_with_hex("hexonly", System.unique_integer([:positive]))

      assert UserToken.fetch(user) == {:error, :no_github_identity}
    end

    test "hands out an unexpired token without asking GitHub" do
      user = expiring_user(8 * 60 * 60)

      assert UserToken.fetch(user) == {:ok, "ghu_old"}
    end

    test "refreshes a token that is about to expire and stores the new tokens" do
      user = expiring_user(60)
      test_pid = self()

      Req.Test.stub(UserToken, fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(test_pid, {:refresh, conn.host, conn.request_path, URI.decode_query(body)})
        Req.Test.json(conn, new_tokens())
      end)

      assert UserToken.fetch(user) == {:ok, "ghu_new"}

      assert_received {:refresh, "github.com", "/login/oauth/access_token",
                       %{
                         "grant_type" => "refresh_token",
                         "refresh_token" => "ghr_old",
                         "client_id" => "Ov23liTestApp",
                         "client_secret" => "test-secret"
                       }}

      identity = github_identity(user)
      assert identity.access_token == "ghu_new"
      assert identity.refresh_token == "ghr_new"
      assert DateTime.diff(identity.access_token_expires_at, DateTime.utc_now()) in 28_790..28_800

      assert UserToken.fetch(user) == {:ok, "ghu_new"}
    end

    test "a refresh GitHub refuses answers :unauthorized and leaves the identity as it was" do
      user = expiring_user(60)
      before = github_identity(user)

      Req.Test.stub(UserToken, fn conn ->
        Req.Test.json(conn, %{
          "error" => "bad_refresh_token",
          "error_description" => "The refresh token passed is incorrect or expired."
        })
      end)

      assert UserToken.fetch(user) == {:error, :unauthorized}
      assert UserToken.message(:unauthorized) == "needs you to sign in with GitHub again"
      assert UserToken.available(user) == nil

      identity = github_identity(user)
      assert identity.access_token == before.access_token
      assert identity.refresh_token == before.refresh_token
      assert identity.access_token_expires_at == before.access_token_expires_at
    end

    test "an expiring token without a refresh token answers :unauthorized" do
      user =
        sign_in_with_github("octo", System.unique_integer([:positive]), %{
          "access_token" => "ghu_old",
          "expires_in" => 60
        })

      assert UserToken.fetch(user) == {:error, :unauthorized}
    end

    test "an unreachable GitHub answers :unreachable" do
      user = expiring_user(60)

      Req.Test.stub(UserToken, &Req.Test.transport_error(&1, :econnrefused))

      assert UserToken.fetch(user) == {:error, :unreachable}
      assert UserToken.message(:unreachable) == "could not reach GitHub"
      assert github_identity(user).access_token == "ghu_old"
    end

    test "an OAuth error that is not a refusal is named" do
      user = expiring_user(60)

      Req.Test.stub(UserToken, fn conn ->
        Req.Test.json(conn, %{
          "error" => "incorrect_client_credentials",
          "error_description" => "The client_id and/or client_secret passed are incorrect."
        })
      end)

      assert {:error, {:oauth_error, text} = reason} = UserToken.fetch(user)
      assert text == "The client_id and/or client_secret passed are incorrect."

      assert UserToken.message(reason) ==
               "could not renew its GitHub access: The client_id and/or client_secret passed are incorrect."

      assert github_identity(user).access_token == "ghu_old"
    end

    test "an OAuth error without a description is named by its code" do
      user = expiring_user(60)

      Req.Test.stub(UserToken, &Req.Test.json(&1, %{"error" => "incorrect_client_credentials"}))

      assert UserToken.fetch(user) == {:error, {:oauth_error, "incorrect_client_credentials"}}
    end

    test "any other failure is logged with the identity and states no cause" do
      user = expiring_user(60)
      identity = github_identity(user)

      Req.Test.stub(UserToken, &Req.Test.json(&1, %{"unexpected" => true}))

      log =
        capture_log([level: :warning], fn ->
          assert UserToken.fetch(user) == {:error, :refresh_failed}
        end)

      assert log =~ identity.id
      refute log =~ "ghr_old"
      refute log =~ "ghu_old"
      assert UserToken.message(:refresh_failed) == "could not renew its GitHub access"
    end

    test "two refreshes at once spend the single-use refresh token only once" do
      user = expiring_user(60)
      spend_refresh_tokens_once()

      results =
        [fn -> UserToken.fetch(user) end, fn -> UserToken.fetch(user) end]
        |> Enum.map(&Task.async/1)
        |> Task.await_many()

      assert results == [{:ok, "ghu_new"}, {:ok, "ghu_new"}]
      assert github_identity(user).refresh_token == "ghr_new"
    end

    test "a refresh that starts from a stale identity uses the tokens the first one stored" do
      user = expiring_user(60)
      stale = github_identity(user)
      spend_refresh_tokens_once()

      assert UserToken.fetch(user) == {:ok, "ghu_new"}

      assert {:ok, identity} =
               Accounts.refresh_github_access_token(stale,
                 actor: user,
                 load: [:access_token, :refresh_token]
               )

      assert identity.access_token == "ghu_new"
      assert identity.refresh_token == "ghr_new"
    end
  end

  describe "the :refresh_access_token action" do
    test "refreshes only for the identity's own user" do
      user = expiring_user(60)
      other = sign_in_with_github("other", System.unique_integer([:positive]))
      identity = github_identity(user)

      assert {:error, %Forbidden{}} =
               Accounts.refresh_github_access_token(identity, actor: other)

      assert {:error, %Forbidden{}} =
               Accounts.refresh_github_access_token(identity, actor: nil)

      assert github_identity(user).access_token == "ghu_old"
    end
  end

  describe "linked?/1" do
    test "is whether the account has a GitHub identity" do
      assert UserToken.linked?(sign_in_with_github("octo", System.unique_integer([:positive])))
      refute UserToken.linked?(sign_in_with_hex("hexonly", System.unique_integer([:positive])))
      refute UserToken.linked?(nil)
    end

    test "does not refresh an expiring token" do
      user = expiring_user(60)

      Req.Test.stub(UserToken, fn _conn -> flunk("linked?/1 asked GitHub for a token") end)

      assert UserToken.linked?(user)
      assert github_identity(user).access_token == "ghu_old"
    end
  end

  describe "message/1" do
    test "states what the action needs" do
      assert UserToken.message(:no_github_identity) == "needs your GitHub account linked"
      assert UserToken.message(:unauthorized) == "needs you to sign in with GitHub again"
    end
  end

  defp expiring_user(expires_in) do
    sign_in_with_github("octo", System.unique_integer([:positive]), %{
      "access_token" => "ghu_old",
      "expires_in" => expires_in,
      "refresh_token" => "ghr_old",
      "refresh_token_expires_in" => 15_811_200
    })
  end

  defp new_tokens do
    %{
      "access_token" => "ghu_new",
      "expires_in" => 28_800,
      "refresh_token" => "ghr_new",
      "refresh_token_expires_in" => 15_811_200,
      "token_type" => "bearer",
      "scope" => ""
    }
  end

  # GitHub accepts each refresh token once and refuses it after that.
  defp spend_refresh_tokens_once do
    spent = start_supervised!({Agent, fn -> MapSet.new() end})

    Req.Test.stub(UserToken, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      %{"refresh_token" => refresh_token} = URI.decode_query(body)

      if Agent.get_and_update(spent, &{refresh_token in &1, MapSet.put(&1, refresh_token)}) do
        Req.Test.json(conn, %{"error" => "bad_refresh_token"})
      else
        Req.Test.json(conn, new_tokens())
      end
    end)
  end

  defp github_identity(user) do
    user
    |> Ash.load!([identities: [:access_token, :refresh_token]], actor: user)
    |> Map.fetch!(:identities)
    |> Enum.find(&(&1.strategy == "github"))
  end
end
