# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserMergeTest do
  @moduledoc """
  Merging one account into another moves everything that references it, then
  deletes it.
  """

  use Varsel.DataCase, async: true

  import Varsel.Fixtures

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Accounts
  alias Varsel.Accounts.User
  alias Varsel.Cases
  alias Varsel.Notifications.Notification
  alias Varsel.Service
  alias Varsel.Test.GitHubApp

  defp console, do: Service.release_console()

  defp count(table, column, user_id) do
    %{rows: [[count]]} =
      Varsel.Repo.query!("SELECT count(*) FROM #{table} WHERE #{column} = $1", [
        Ecto.UUID.dump!(user_id)
      ])

    count
  end

  defp gone?(user), do: match?({:error, %Invalid{}}, Ash.get(User, user.id, authorize?: false))

  describe "what moves" do
    test "the linked providers, so either one signs in to the surviving account" do
      from = sign_in_with_hex("alice_hex", "alice_hex")
      into = register_user("alice")

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("user_identities", "user_id", into.id) == 2
      assert sign_in_with_hex("alice_hex", "alice_hex").id == into.id
    end

    test "API keys" do
      from = register_user("from")
      into = register_user("into")
      {_key, _plaintext} = create_api_key(from)

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("api_keys", "user_id", into.id) == 1
    end

    test "case work: assignments, comments, proposals and credits" do
      poc = register_user("poc", :poc)
      from = register_user("from", :poc)
      into = register_user("into")
      case_record = open_case(poc)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: from.id}, actor: poc)
      Cases.post_case_comment!(%{case_id: case_record.id, body: "Mine"}, actor: from)

      Cases.add_case_credit!(
        %{case_id: case_record.id, user_id: from.id, name: "From", credit_type: :finder},
        actor: poc
      )

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("case_assignments", "user_id", into.id) == 1
      assert count("case_comments", "author_id", into.id) == 1
      assert count("case_credits", "user_id", into.id) == 1
    end

    test "an assignment both accounts hold stays once" do
      poc = register_user("poc", :poc)
      from = register_user("from")
      into = register_user("into")
      case_record = open_case(poc)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: from.id}, actor: poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: into.id}, actor: poc)

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("case_assignments", "user_id", into.id) == 1
    end

    test "comment reactions, once where both accounts gave the same one" do
      poc = register_user("poc", :poc)
      from = register_user("from", :poc)
      into = register_user("into", :poc)
      case_record = open_case(poc)
      comment = Cases.post_case_comment!(%{case_id: case_record.id, body: "Patched"}, actor: poc)

      for {user, emoji} <- [{from, :rocket}, {from, :eyes}, {into, :rocket}] do
        Cases.react_to_case_comment!(
          %{case_id: case_record.id, comment_id: comment.id, emoji: emoji},
          actor: user
        )
      end

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("case_comment_reactions", "user_id", into.id) == 2
    end

    test "reports" do
      from = register_user("from")
      into = register_user("into")

      Cases.submit_vulnerability_report!(
        %{
          report_json: %{"package" => "acme_lib", "details" => "leaks secrets"},
          summary: "Leaks secrets",
          confirms_criteria: true,
          confirms_in_scope: true
        },
        actor: from
      )

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("vulnerability_reports", "reporter_id", into.id) == 1
    end

    test "GitHub installations, once where both accounts reach one" do
      from = register_user("from")
      into = register_user("into")
      GitHubApp.seed_installation(%{id: 7, account: "acme"})
      GitHubApp.seed_installation(%{id: 8, account: "other"})
      GitHubApp.seed_user_installations(from, [7, 8])
      GitHubApp.seed_user_installations(into, [7])

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("github_user_installations", "user_id", into.id) == 2
    end

    test "notifications, once where both accounts hold the same unread one" do
      poc = register_user("poc", :poc)
      from = register_user("from")
      into = register_user("into")
      case_record = open_case(poc)

      for {user, kind} <- [
            {from, :comment_posted},
            {from, :review_requested},
            {into, :comment_posted}
          ] do
        Ash.Seed.seed!(Notification, %{
          user_id: user.id,
          kind: kind,
          case_id: case_record.id,
          last_event_at: DateTime.utc_now()
        })
      end

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert count("notifications", "user_id", into.id) == 2
    end
  end

  describe "the merged account" do
    test "is deleted" do
      from = register_user("from")
      into = register_user("into")

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert gone?(from)
      refute gone?(into)
    end

    test "has its sessions revoked" do
      from = register_user("from")
      into = register_user("into")

      Accounts.merge_user_into!(from, into.id, actor: console())

      assert %{rows: [["revocation"]]} =
               Varsel.Repo.query!("SELECT purpose FROM tokens WHERE subject = $1", [
                 "user?id=#{from.id}"
               ])
    end
  end

  describe "refused merges" do
    test "into itself" do
      user = register_user("alice")

      assert {:error, %Invalid{}} = Accounts.merge_user_into(user, user.id, actor: console())
      refute gone?(user)
    end

    test "into an account that does not exist" do
      user = register_user("alice")

      assert {:error, %Invalid{}} =
               Accounts.merge_user_into(user, Ash.UUID.generate(), actor: console())

      refute gone?(user)
      assert count("user_identities", "user_id", user.id) == 1
    end
  end

  describe "who may merge" do
    test "the release console" do
      from = register_user("from")
      into = register_user("into")

      assert :ok = Accounts.merge_user_into(from, into.id, actor: console())
    end

    test "not a POC" do
      poc = register_user("poc", :poc)
      from = register_user("from")
      into = register_user("into")

      assert {:error, %Forbidden{}} = Accounts.merge_user_into(from, into.id, actor: poc)
    end

    test "not the account itself" do
      from = register_user("from")
      into = register_user("into")

      assert {:error, %Forbidden{}} = Accounts.merge_user_into(from, into.id, actor: from)
    end

    test "not an anonymous caller" do
      from = register_user("from")
      into = register_user("into")

      assert {:error, %Forbidden{}} = Accounts.merge_user_into(from, into.id, actor: nil)
    end
  end

  # `Varsel.Accounts.User.Changes.RepointToMergeTarget` lists every column
  # that references users. A new one has to be added there, or the merge
  # deletes or nulls its rows with the account.
  test "every foreign key to users is one the merge repoints" do
    %{rows: rows} =
      Varsel.Repo.query!("""
      SELECT source.relname, attribute.attname
      FROM pg_constraint AS fk
      JOIN pg_class AS source ON source.oid = fk.conrelid
      JOIN pg_class AS target ON target.oid = fk.confrelid
      JOIN pg_attribute AS attribute
        ON attribute.attrelid = fk.conrelid AND attribute.attnum = ANY (fk.conkey)
      WHERE fk.contype = 'f' AND target.relname = 'users'
      """)

    assert Enum.sort(Enum.map(rows, &List.to_tuple/1)) == [
             {"api_keys", "user_id"},
             {"case_assignments", "user_id"},
             {"case_comment_reactions", "user_id"},
             {"case_comments", "author_id"},
             {"case_credits", "user_id"},
             {"case_proposals", "author_id"},
             {"case_proposals", "resolved_by_id"},
             {"github_manual_requests", "user_id"},
             {"github_user_installations", "user_id"},
             {"notifications", "user_id"},
             {"user_identities", "user_id"},
             {"vulnerability_reports", "reporter_id"}
           ]
  end
end
