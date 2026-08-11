# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInviteTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Accounts.GitHub
  alias Varsel.Cases
  alias Varsel.Fixtures

  setup do
    Application.put_env(:varsel, :hex_stub_users, ["alice"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_users) end)

    Req.Test.stub(GitHub, fn conn ->
      case conn.request_path |> Path.basename() |> URI.decode() |> String.downcase() do
        "octocat" -> Req.Test.json(conn, %{"login" => "octocat"})
        _unknown -> Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    poc = Fixtures.register_user("invite_poc", :poc)

    %{poc: poc, case: Fixtures.open_case(poc)}
  end

  describe ":invite" do
    test "names someone by their GitHub handle", %{poc: poc, case: case_record} do
      invite =
        Cases.invite_to_case!(
          %{case_id: case_record.id, strategy: :github, username: "octocat"},
          actor: poc
        )

      assert invite.strategy == :github
      assert to_string(invite.username) == "octocat"
    end

    test "names someone by their hex.pm handle", %{poc: poc, case: case_record} do
      invite =
        Cases.invite_to_case!(
          %{case_id: case_record.id, strategy: :hex, username: "alice"},
          actor: poc
        )

      assert invite.strategy == :hex
    end

    test "stores the handle as the provider spells it", %{poc: poc, case: case_record} do
      invite =
        Cases.invite_to_case!(
          %{case_id: case_record.id, strategy: :github, username: "  OctoCat  "},
          actor: poc
        )

      assert to_string(invite.username) == "octocat"
    end

    test "a handle the provider does not know is refused", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{} = error} =
               Cases.invite_to_case(
                 %{case_id: case_record.id, strategy: :github, username: "ghost"},
                 actor: poc
               )

      assert Exception.message(error) =~ "not a GitHub account"
    end

    test "the same handle cannot be invited to one case twice", %{poc: poc, case: case_record} do
      attrs = %{case_id: case_record.id, strategy: :github, username: "octocat"}

      assert {:ok, _} = Cases.invite_to_case(attrs, actor: poc)

      assert {:error, %Invalid{}} =
               Cases.invite_to_case(%{attrs | username: "OCTOCAT"}, actor: poc)
    end

    test "someone with no business on the case cannot invite to it", %{case: case_record} do
      outsider = Fixtures.register_user("invite_outsider", :supporter)

      assert {:error, %Forbidden{}} =
               Cases.invite_to_case(
                 %{case_id: case_record.id, strategy: :github, username: "octocat"},
                 actor: outsider
               )
    end
  end

  describe ":for_identity" do
    test "finds the invites naming a handle, whatever its casing", %{
      poc: poc,
      case: case_record
    } do
      Cases.invite_to_case!(
        %{case_id: case_record.id, strategy: :github, username: "octocat"},
        actor: poc
      )

      assert [invite] =
               Cases.list_case_invites_for_identity!(:github, "OctoCat", authorize?: false)

      assert invite.case_id == case_record.id
    end

    test "does not confuse one provider's handle for another's", %{poc: poc, case: case_record} do
      Cases.invite_to_case!(
        %{case_id: case_record.id, strategy: :hex, username: "alice"},
        actor: poc
      )

      assert [] = Cases.list_case_invites_for_identity!(:github, "alice", authorize?: false)
    end
  end

  describe ":grant_access" do
    test "assigns outright when the handle is one we already hold", %{
      poc: poc,
      case: case_record
    } do
      known = Fixtures.register_user("octocat")

      assert {:ok, _} = Cases.grant_case_access(case_record, :github, "octocat", actor: poc)

      assignees =
        case_record
        |> Ash.load!(:assignments, actor: poc)
        |> Map.fetch!(:assignments)
        |> Enum.map(& &1.user_id)

      assert known.id in assignees
      assert Cases.list_case_invites!(actor: poc) == []
    end

    test "invites when the handle belongs to nobody here yet", %{poc: poc, case: case_record} do
      assert {:ok, _} = Cases.grant_case_access(case_record, :github, "octocat", actor: poc)

      assert [invite] = Cases.list_case_invites!(actor: poc)
      assert to_string(invite.username) == "octocat"
    end

    test "an assigned supporter may grant", %{poc: poc, case: case_record} do
      supporter = Fixtures.register_user("grant_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      assert {:ok, _} =
               Cases.grant_case_access(case_record, :github, "octocat", actor: supporter)
    end

    test "a supporter who is not on the case may not", %{poc: poc, case: case_record} do
      stranger = Fixtures.register_user("grant_stranger", :supporter)

      assert {:error, %Forbidden{}} =
               Cases.grant_case_access(case_record, :github, "octocat", actor: stranger)

      assert Cases.list_case_invites!(actor: poc) == []
    end
  end
end
