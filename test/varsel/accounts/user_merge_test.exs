# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserMergeTest do
  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias Varsel.Accounts
  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity

  defp link_identity(user, strategy, username) do
    Ash.create!(
      UserIdentity,
      %{
        user_id: user.id,
        strategy: strategy,
        user_info: %{
          "sub" => username,
          "preferred_username" => username,
          "email" => "#{username}@example.com"
        },
        oauth_tokens: %{"access_token" => "token"}
      },
      action: :upsert,
      authorize?: false
    )
  end

  defp identities_of(user) do
    user
    |> Ash.load!([:identities], authorize?: false)
    |> Map.fetch!(:identities)
    |> Enum.map(& &1.strategy)
    |> Enum.sort()
  end

  test "the merged account's providers move to the surviving one" do
    keep = register_user("keep")
    merge = register_user("merge")
    link_identity(merge, "hex", "merge_hex")

    Accounts.merge_user_into!(merge, keep.id, actor: merge)

    assert identities_of(keep) == ["github", "github", "hex"]
    assert identities_of(merge) == []
  end

  test "the merged account is marked as merged rather than deleted" do
    keep = register_user("keep")
    merge = register_user("merge")

    Accounts.merge_user_into!(merge, keep.id, actor: merge)

    merged = Ash.get!(User, merge.id, authorize?: false)

    assert merged.merged_into_id == keep.id
  end

  test "live work moves so it stays reachable" do
    poc = register_user("poc", :poc)
    keep = register_user("keep")
    merge = register_user("merge")

    case_record = open_case(poc)
    Varsel.Cases.assign_case_user!(%{case_id: case_record.id, user_id: merge.id}, actor: poc)
    {api_key, _plaintext} = create_api_key(merge)

    Accounts.merge_user_into!(merge, keep.id, actor: merge)

    assignment_user_ids =
      [actor: poc] |> Varsel.Cases.list_case_assignments!() |> Enum.map(& &1.user_id)

    assert keep.id in assignment_user_ids
    refute merge.id in assignment_user_ids

    assert Ash.get!(Varsel.Accounts.ApiKey, api_key.id, authorize?: false).user_id == keep.id
  end

  test "paper-trail history stays with the account that made it" do
    keep = register_user("keep")
    merge = register_user("merge")

    versions_before =
      Varsel.Repo.query!("SELECT count(*) FROM users_versions WHERE user_id = $1", [
        Ecto.UUID.dump!(merge.id)
      ])

    Accounts.merge_user_into!(merge, keep.id, actor: merge)

    versions_after =
      Varsel.Repo.query!("SELECT count(*) FROM users_versions WHERE user_id = $1", [
        Ecto.UUID.dump!(merge.id)
      ])

    # The merge itself adds a version; what matters is that the existing ones
    # were not repointed away from the account that authored them.
    assert hd(hd(versions_after.rows)) >= hd(hd(versions_before.rows))
  end

  test "nobody merges an account they are not signed in as" do
    keep = register_user("keep")
    merge = register_user("merge")
    poc = register_user("poc", :poc)

    assert {:error, %Ash.Error.Forbidden{}} =
             Accounts.merge_user_into(merge, keep.id, actor: poc)
  end
end
