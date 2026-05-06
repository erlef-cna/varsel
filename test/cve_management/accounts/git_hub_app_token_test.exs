# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts.GitHubAppTokenTest do
  use CveManagement.DataCase, async: false

  alias Ash.Error.Forbidden
  alias CveManagement.Accounts.GitHubAppToken
  alias CveManagement.GitHub.AppClient

  @expires_at ~U[2026-05-05 17:00:00Z]

  defp create_user do
    CveManagement.Accounts.User
    |> Ash.Changeset.for_create(
      :register_with_github,
      %{
        user_info: %{
          "sub" => System.unique_integer([:positive]),
          "preferred_username" => "testuser",
          "name" => "Test User",
          "email" => "test@example.com"
        },
        oauth_tokens: %{"access_token" => "gho_test"}
      },
      authorize?: false
    )
    |> Ash.create!(authorize?: false)
  end

  defp upsert_token(user, opts \\ []) do
    GitHubAppToken
    |> Ash.Changeset.for_create(:upsert_from_oauth, %{
      user_id: user.id,
      access_token: Keyword.get(opts, :access_token, "ghu_test_access"),
      refresh_token: Keyword.get(opts, :refresh_token, "ghr_test_refresh"),
      expires_at: Keyword.get(opts, :expires_at, @expires_at)
    })
    |> Ash.create(actor: user)
  end

  defp stub_github_refresh(response_body) do
    Req.Test.stub(AppClient, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, Jason.encode!(response_body))
    end)
  end

  describe "upsert_from_oauth" do
    test "creates a token for the user" do
      user = create_user()

      assert {:ok, token} = upsert_token(user)
      assert token.user_id == user.id
      assert token.status == :valid
      assert token.expires_at == DateTime.truncate(@expires_at, :second)
    end

    test "updates existing token on second oauth connect" do
      user = create_user()

      assert {:ok, _} = upsert_token(user, access_token: "ghu_first", refresh_token: "ghr_first")

      assert {:ok, _} =
               upsert_token(user, access_token: "ghu_second", refresh_token: "ghr_second")

      assert Ash.count!(GitHubAppToken, authorize?: false) == 1
    end

    test "stored tokens are encrypted in the database" do
      user = create_user()
      {:ok, _} = upsert_token(user, access_token: "ghu_plaintext")

      [row] =
        CveManagement.Repo.all(from(t in "git_hub_app_tokens", select: t.encrypted_access_token))

      assert row
      refute row =~ "ghu_plaintext"
    end

    test "decrypts access_token via calculation" do
      user = create_user()
      {:ok, token} = upsert_token(user, access_token: "ghu_roundtrip")

      loaded = Ash.load!(token, [:access_token], authorize?: false)
      assert loaded.access_token == "ghu_roundtrip"
    end

    test "decrypts refresh_token via calculation" do
      user = create_user()
      {:ok, token} = upsert_token(user, refresh_token: "ghr_roundtrip")

      loaded = Ash.load!(token, [:refresh_token], authorize?: false)
      assert loaded.refresh_token == "ghr_roundtrip"
    end

    test "denies creating a token for a different user" do
      user = create_user()
      other_user = create_user()

      result =
        GitHubAppToken
        |> Ash.Changeset.for_create(:upsert_from_oauth, %{
          user_id: other_user.id,
          access_token: "ghu_test",
          refresh_token: "ghr_test",
          expires_at: @expires_at
        })
        |> Ash.create(actor: user)

      assert {:error, %Forbidden{}} = result
    end
  end

  describe "read" do
    test "user can only read their own token" do
      user = create_user()
      other_user = create_user()
      {:ok, _} = upsert_token(user)

      assert {:ok, [token]} = Ash.read(GitHubAppToken, actor: user)
      assert token.user_id == user.id

      assert {:ok, []} = Ash.read(GitHubAppToken, actor: other_user)
    end
  end

  describe "refresh" do
    test "updates tokens on successful GitHub response" do
      user = create_user()
      {:ok, token} = upsert_token(user, refresh_token: "ghr_old")

      stub_github_refresh(%{
        "access_token" => "ghu_new",
        "refresh_token" => "ghr_new",
        "expires_in" => 28_800,
        "token_type" => "bearer"
      })

      assert {:ok, refreshed} =
               token
               |> Ash.Changeset.for_update(:refresh, %{})
               |> Ash.update(authorize?: false)

      assert refreshed.status == :valid

      loaded = Ash.load!(refreshed, [:access_token, :refresh_token], authorize?: false)
      assert loaded.access_token == "ghu_new"
      assert loaded.refresh_token == "ghr_new"
    end

    test "marks token invalid on GitHub error response" do
      user = create_user()
      {:ok, token} = upsert_token(user)

      stub_github_refresh(%{"error" => "bad_refresh_token"})

      assert {:ok, refreshed} =
               token
               |> Ash.Changeset.for_update(:refresh, %{})
               |> Ash.update(authorize?: false)

      assert refreshed.status == :invalid
    end
  end

  describe "mark_invalid" do
    test "user can mark their own token invalid" do
      user = create_user()
      {:ok, token} = upsert_token(user)

      assert {:ok, updated} =
               token
               |> Ash.Changeset.for_update(:mark_invalid, %{})
               |> Ash.update(actor: user)

      assert updated.status == :invalid
    end

    test "user cannot mark another user's token invalid" do
      user = create_user()
      other_user = create_user()
      {:ok, token} = upsert_token(user)

      assert {:error, %Forbidden{}} =
               token
               |> Ash.Changeset.for_update(:mark_invalid, %{})
               |> Ash.update(actor: other_user)
    end
  end
end
