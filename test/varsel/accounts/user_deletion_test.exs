# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserDeletionTest do
  @moduledoc """
  Deleting an account takes what it *was* and keeps what it *wrote*.
  """

  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias Ash.Error.Forbidden
  alias Varsel.Accounts
  alias Varsel.Accounts.User
  alias Varsel.Cases

  defp count(table, column, user_id) do
    %{rows: [[count]]} =
      Varsel.Repo.query!("SELECT count(*) FROM #{table} WHERE #{column} = $1", [
        Ecto.UUID.dump!(user_id)
      ])

    count
  end

  describe "what goes with the account" do
    test "its linked providers" do
      user = register_user("alice")

      assert count("user_identities", "user_id", user.id) == 1
      Accounts.delete_user!(user, actor: user)
      assert count("user_identities", "user_id", user.id) == 0
    end

    test "its API keys" do
      user = register_user("alice")
      {_key, _plaintext} = create_api_key(user)

      assert count("api_keys", "user_id", user.id) == 1
      Accounts.delete_user!(user, actor: user)
      assert count("api_keys", "user_id", user.id) == 0
    end

    # Tokens have no foreign key to users — they are keyed by subject — so
    # nothing removes them on their own. A live session token for an account
    # that no longer exists is worth ending rather than leaving to expire.
    test "its sessions, revoked rather than left to expire" do
      user = register_user("alice")

      assert %{rows: [["user"]]} =
               Varsel.Repo.query!("SELECT purpose FROM tokens WHERE subject = $1", [
                 "user?id=#{user.id}"
               ])

      Accounts.delete_user!(user, actor: user)

      assert %{rows: [["revocation"]]} =
               Varsel.Repo.query!("SELECT purpose FROM tokens WHERE subject = $1", [
                 "user?id=#{user.id}"
               ])
    end

    test "its case assignments, which only it could act on" do
      poc = register_user("poc", :poc)
      user = register_user("alice")
      case_record = open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: user.id}, actor: poc)

      assert count("case_assignments", "user_id", user.id) == 1
      Accounts.delete_user!(user, actor: poc)
      assert count("case_assignments", "user_id", user.id) == 0
    end
  end

  describe "what stays behind" do
    test "comments keep their text and lose their author" do
      poc = register_user("poc", :poc)
      case_record = open_case(poc)

      comment =
        Cases.post_case_comment!(%{case_id: case_record.id, body: "Worth a look"}, actor: poc)

      Accounts.delete_user!(poc, actor: poc)

      kept = Ash.get!(Cases.Comment, comment.id, authorize?: false)

      assert kept.body == "Worth a look"
      assert kept.author_id == nil
    end

    test "reports keep their contents and lose their reporter" do
      reporter = register_user("reporter")

      report =
        Varsel.CVE.submit_vulnerability_report!(
          %{
            report_json: %{"package" => "acme_lib", "details" => "leaks secrets"},
            summary: "Leaks secrets",
            confirms_criteria: true,
            confirms_in_scope: true
          },
          actor: reporter
        )

      Accounts.delete_user!(reporter, actor: reporter)

      kept = Ash.get!(Varsel.CVE.VulnerabilityReport, report.id, authorize?: false)

      assert kept.reporter_id == nil
    end

    # The audit trail is the reason the version tables have no foreign key to
    # users: an entry has to keep saying which account made a change, and a
    # deleted account is exactly when that matters most.
    test "paper-trail versions keep the id of the account that acted" do
      user = register_user("alice")
      {_key, _plaintext} = create_api_key(user)

      before_delete = count("api_keys_versions", "user_id", user.id)
      assert before_delete > 0

      Accounts.delete_user!(user, actor: user)

      assert count("api_keys_versions", "user_id", user.id) == before_delete

      # ...even though the account itself is really gone.
      assert {:error, %Ash.Error.Invalid{}} = Ash.get(User, user.id, authorize?: false)
    end
  end

  describe "who may delete" do
    test "a user deletes their own account" do
      user = register_user("alice")

      assert :ok = Accounts.delete_user(user, actor: user)
    end

    test "a POC deletes someone else's" do
      poc = register_user("poc", :poc)
      user = register_user("alice")

      assert :ok = Accounts.delete_user(user, actor: poc)
    end

    test "a POC deletes another POC" do
      poc = register_user("poc", :poc)
      other = register_user("other", :poc)

      assert :ok = Accounts.delete_user(other, actor: poc)
    end

    test "nobody else may" do
      alice = register_user("alice")
      bob = register_user("bob")

      assert {:error, %Forbidden{}} = Accounts.delete_user(alice, actor: bob)
    end

    test "an anonymous caller may not" do
      alice = register_user("alice")

      assert {:error, %Forbidden{}} = Accounts.delete_user(alice, actor: nil)
    end
  end
end
