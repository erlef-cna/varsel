# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubWatchedTargetTest do
  use CveManagement.DataCase, async: false

  alias Ash.Error.Forbidden
  alias CveManagement.Accounts.GitHubAppToken
  alias CveManagement.GitHub.AdvisoryClient
  alias CveManagement.ReportChannels.GitHubAdvisory
  alias CveManagement.ReportChannels.GitHubWatchedTarget

  @advisory_json %{
    "ghsa_id" => "GHSA-aaaa-bbbb-cccc",
    "cve_id" => nil,
    "summary" => "Watched advisory",
    "description" => nil,
    "severity" => "medium",
    "state" => "draft",
    "url" => "https://api.github.com/repos/erlef/mylib/security-advisories/GHSA-aaaa-bbbb-cccc",
    "html_url" => "https://github.com/erlef/mylib/security-advisories/GHSA-aaaa-bbbb-cccc",
    "author" => nil,
    "publisher" => nil,
    "created_at" => "2026-01-01T00:00:00Z",
    "updated_at" => "2026-01-02T00:00:00Z",
    "published_at" => nil,
    "closed_at" => nil,
    "withdrawn_at" => nil,
    "vulnerabilities" => [],
    "cvss_severities" => nil,
    "cwe_ids" => [],
    "identifiers" => [],
    "credits" => [],
    "credits_detailed" => [],
    "collaborating_users" => [],
    "collaborating_teams" => [],
    "submission" => nil,
    "private_fork" => nil
  }

  defp create_user do
    CveManagement.Accounts.User
    |> Ash.Changeset.for_create(
      :register_with_github,
      %{
        user_info: %{
          "sub" => System.unique_integer([:positive]),
          "preferred_username" => "user#{System.unique_integer([:positive])}",
          "name" => "Test User",
          "email" => "test#{System.unique_integer([:positive])}@example.com"
        },
        oauth_tokens: %{"access_token" => "gho_test"}
      },
      authorize?: false
    )
    |> Ash.create!(authorize?: false)
  end

  defp create_token(user) do
    GitHubAppToken
    |> Ash.Changeset.for_create(:upsert_from_oauth, %{
      user_id: user.id,
      access_token: "ghu_test_access",
      refresh_token: "ghr_test_refresh",
      expires_at: ~U[2030-01-01 00:00:00Z]
    })
    |> Ash.create!(authorize?: false)
  end

  defp stub_advisories(list) do
    Req.Test.stub(AdvisoryClient, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, Jason.encode!(list))
    end)
  end

  describe "create" do
    test "user can create a repo target for themselves" do
      user = create_user()

      assert {:ok, target} =
               GitHubWatchedTarget
               |> Ash.Changeset.for_create(:create, %{
                 owner: "erlef",
                 repo: "mylib",
                 user_id: user.id
               })
               |> Ash.create(actor: user)

      assert target.owner == "erlef"
      assert target.repo == "mylib"
      assert target.user_id == user.id
      assert target.synced_at == nil
    end

    test "user can create an org target (no repo)" do
      user = create_user()

      assert {:ok, target} =
               GitHubWatchedTarget
               |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: user.id})
               |> Ash.create(actor: user)

      assert target.owner == "erlef"
      assert target.repo == nil
    end

    test "user cannot create a target for another user" do
      user = create_user()
      other = create_user()

      assert {:error, %Forbidden{}} =
               GitHubWatchedTarget
               |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: other.id})
               |> Ash.create(actor: user)
    end

    test "enforces unique constraint on user + owner + repo" do
      user = create_user()

      GitHubWatchedTarget
      |> Ash.Changeset.for_create(:create, %{owner: "erlef", repo: "mylib", user_id: user.id})
      |> Ash.create!(authorize?: false)

      assert {:error, _} =
               GitHubWatchedTarget
               |> Ash.Changeset.for_create(:create, %{
                 owner: "erlef",
                 repo: "mylib",
                 user_id: user.id
               })
               |> Ash.create(authorize?: false)
    end
  end

  describe "read" do
    test "user can only read their own targets" do
      user = create_user()
      other = create_user()

      GitHubWatchedTarget
      |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: user.id})
      |> Ash.create!(authorize?: false)

      assert {:ok, [_]} = Ash.read(GitHubWatchedTarget, actor: user)
      assert {:ok, []} = Ash.read(GitHubWatchedTarget, actor: other)
    end
  end

  describe "destroy" do
    test "user can destroy their own target" do
      user = create_user()

      target =
        GitHubWatchedTarget
        |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: user.id})
        |> Ash.create!(authorize?: false)

      assert :ok = Ash.destroy(target, actor: user)
      assert Ash.count!(GitHubWatchedTarget, authorize?: false) == 0
    end

    test "user cannot destroy another user's target" do
      user = create_user()
      other = create_user()

      target =
        GitHubWatchedTarget
        |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: user.id})
        |> Ash.create!(authorize?: false)

      assert {:error, %Forbidden{}} = Ash.destroy(target, actor: other)
    end
  end

  describe "sync (repo)" do
    test "fetches repo advisories and ingests them" do
      user = create_user()
      create_token(user)
      stub_advisories([@advisory_json])

      target =
        GitHubWatchedTarget
        |> Ash.Changeset.for_create(:create, %{owner: "erlef", repo: "mylib", user_id: user.id})
        |> Ash.create!(authorize?: false)

      target
      |> Ash.Changeset.for_update(:sync, %{}, authorize?: false)
      |> Ash.update!(authorize?: false)

      assert Ash.count!(GitHubAdvisory, authorize?: false) == 1
      assert [advisory] = Ash.read!(GitHubAdvisory, authorize?: false)
      assert advisory.ghsa_id == "GHSA-aaaa-bbbb-cccc"
    end

    test "sets synced_at after sync" do
      user = create_user()
      create_token(user)
      stub_advisories([])

      target =
        GitHubWatchedTarget
        |> Ash.Changeset.for_create(:create, %{owner: "erlef", repo: "mylib", user_id: user.id})
        |> Ash.create!(authorize?: false)

      updated =
        target
        |> Ash.Changeset.for_update(:sync, %{}, authorize?: false)
        |> Ash.update!(authorize?: false)

      assert updated.synced_at
    end

    test "is idempotent: syncing twice does not duplicate advisories" do
      user = create_user()
      create_token(user)
      stub_advisories([@advisory_json])

      target =
        GitHubWatchedTarget
        |> Ash.Changeset.for_create(:create, %{owner: "erlef", repo: "mylib", user_id: user.id})
        |> Ash.create!(authorize?: false)

      target
      |> Ash.Changeset.for_update(:sync, %{}, authorize?: false)
      |> Ash.update!(authorize?: false)

      stub_advisories([@advisory_json])

      target
      |> Ash.Changeset.for_update(:sync, %{}, authorize?: false)
      |> Ash.update!(authorize?: false)

      assert Ash.count!(GitHubAdvisory, authorize?: false) == 1
    end
  end

  describe "sync (org)" do
    test "fetches org advisories and ingests them" do
      user = create_user()
      create_token(user)
      stub_advisories([@advisory_json])

      target =
        GitHubWatchedTarget
        |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: user.id})
        |> Ash.create!(authorize?: false)

      target
      |> Ash.Changeset.for_update(:sync, %{}, authorize?: false)
      |> Ash.update!(authorize?: false)

      assert Ash.count!(GitHubAdvisory, authorize?: false) == 1
    end
  end

  describe "oban trigger" do
    test "schedules sync for targets not yet synced" do
      user = create_user()
      create_token(user)
      stub_advisories([])

      GitHubWatchedTarget
      |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: user.id})
      |> Ash.create!(authorize?: false)

      result = AshOban.Test.schedule_and_run_triggers({GitHubWatchedTarget, :sync})
      assert result.success >= 1
      assert result.failure == 0
    end

    test "does not schedule sync for recently synced targets" do
      user = create_user()
      create_token(user)
      stub_advisories([])

      target =
        GitHubWatchedTarget
        |> Ash.Changeset.for_create(:create, %{owner: "erlef", user_id: user.id})
        |> Ash.create!(authorize?: false)

      # Mark as recently synced
      Ash.update!(target, %{}, action: :sync, authorize?: false)

      result = AshOban.Test.schedule_and_run_triggers({GitHubWatchedTarget, :sync})
      # Scheduler should not pick up a recently-synced target; the create job may still be pending
      assert result.failure == 0
      assert result.cancelled >= 1 || result.success == 0
    end
  end
end
