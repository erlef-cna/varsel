# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCreditTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Accounts
  alias Varsel.Accounts.GitHub
  alias Varsel.Cases
  alias Varsel.Cases.CaseCredit
  alias Varsel.Fixtures
  alias Varsel.HexPm

  setup do
    Req.Test.stub(HexPm, fn conn ->
      case conn.path_info do
        ["api", "users", "alice", "contact"] ->
          Req.Test.json(conn, %{"username" => "alice", "name" => "Alice Example", "email" => nil})

        _unknown ->
          Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    Req.Test.stub(GitHub, fn conn ->
      case conn.request_path |> Path.basename() |> URI.decode() |> String.downcase() do
        "octocat" ->
          Req.Test.json(conn, %{"login" => "octocat", "name" => "The Octocat", "email" => nil})

        "hermit" ->
          Req.Test.json(conn, %{"login" => "hermit", "name" => "", "email" => nil})

        "newcomer" ->
          Req.Test.json(conn, %{"login" => "newcomer", "name" => "New Comer", "email" => nil})

        _unknown ->
          Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    poc = Fixtures.register_user("credit_poc", :poc)
    member = Fixtures.register_user("maennchen")

    %{poc: poc, member: member, case: Fixtures.open_case(poc)}
  end

  defp handles(credit), do: Enum.map(credit.handles, &{&1.strategy, to_string(&1.username)})

  describe ":add for an account" do
    test "takes the credit the account asked for", %{poc: poc, member: member, case: case_record} do
      Accounts.set_user_credit!(
        member,
        %{credit_name: "Jonatan Männchen", credit_organization: "EEF"},
        actor: member
      )

      credit =
        Cases.add_case_credit!(
          %{case_id: case_record.id, user_id: member.id, credit_type: :analyst},
          actor: poc
        )

      assert credit.name == "Jonatan Männchen"
      assert credit.organization == "EEF"
      assert credit.user_id == member.id
      assert handles(credit) == [github: "maennchen"]
    end

    test "falls back to the display name when the account asked for nothing", %{
      poc: poc,
      member: member,
      case: case_record
    } do
      credit =
        Cases.add_case_credit!(
          %{case_id: case_record.id, user_id: member.id, credit_type: :finder},
          actor: poc
        )

      assert credit.name == "maennchen name"
      assert credit.organization == nil
    end

    test "keeps the name and organization the caller gave", %{
      poc: poc,
      member: member,
      case: case_record
    } do
      Accounts.set_user_credit!(
        member,
        %{credit_name: "Jonatan Männchen", credit_organization: "EEF"},
        actor: member
      )

      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            user_id: member.id,
            name: "J. Männchen",
            organization: "Erlef",
            credit_type: :finder
          },
          actor: poc
        )

      assert credit.name == "J. Männchen"
      assert credit.organization == "Erlef"
    end

    test "links the account holding a handle, spelled as it signed in", %{
      poc: poc,
      member: member,
      case: case_record
    } do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            credit_type: :finder,
            handles: [%{strategy: :github, username: " MAENNCHEN "}]
          },
          actor: poc
        )

      assert credit.user_id == member.id
      assert credit.name == "maennchen name"
      assert handles(credit) == [github: "maennchen"]
    end
  end

  describe ":add by handle" do
    test "confirms the handle at its provider and takes the profile name", %{
      poc: poc,
      case: case_record
    } do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            credit_type: :finder,
            handles: [%{strategy: :github, username: "OctoCat"}]
          },
          actor: poc
        )

      assert credit.user_id == nil
      assert credit.name == "The Octocat"
      assert handles(credit) == [github: "octocat"]
    end

    test "asks hex.pm", %{poc: poc, case: case_record} do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            credit_type: :reporter,
            handles: [%{strategy: :hex, username: "alice"}]
          },
          actor: poc
        )

      assert credit.name == "Alice Example"
      assert handles(credit) == [hex: "alice"]
    end

    test "refuses a handle the provider does not know", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{errors: [error]}} =
               Cases.add_case_credit(
                 %{
                   case_id: case_record.id,
                   credit_type: :finder,
                   handles: [%{strategy: :github, username: "nobody"}]
                 },
                 actor: poc
               )

      assert error.field == :handles
      assert error.message =~ "nobody is not a GitHub account"
    end

    test "still needs a name when the profile lists none", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{errors: [error]}} =
               Cases.add_case_credit(
                 %{
                   case_id: case_record.id,
                   credit_type: :finder,
                   handles: [%{strategy: :github, username: "hermit"}]
                 },
                 actor: poc
               )

      assert error.field == :name
    end

    test "keeps one handle per provider, the first given", %{poc: poc, case: case_record} do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            credit_type: :finder,
            handles: [
              %{strategy: :github, username: "octocat"},
              %{strategy: :github, username: "nobody"}
            ]
          },
          actor: poc
        )

      assert handles(credit) == [github: "octocat"]
    end
  end

  describe ":edit" do
    test "leaves stored handles alone and confirms only new ones", %{poc: poc, case: case_record} do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            credit_type: :finder,
            handles: [%{strategy: :github, username: "octocat"}]
          },
          actor: poc
        )

      Req.Test.stub(GitHub, fn conn -> Plug.Conn.send_resp(conn, 404, "{}") end)

      edited = Cases.edit_case_credit!(credit, %{name: "Octo Cat"}, actor: poc)
      assert edited.name == "Octo Cat"
      assert handles(edited) == [github: "octocat"]

      assert {:error, %Invalid{errors: [error]}} =
               Cases.edit_case_credit(
                 edited,
                 %{
                   handles: [
                     %{strategy: :github, username: "octocat"},
                     %{strategy: :hex, username: "nobody"}
                   ]
                 },
                 actor: poc
               )

      assert error.field == :handles
    end
  end

  describe ":refresh" do
    test "re-copies the account's current preference", %{
      poc: poc,
      member: member,
      case: case_record
    } do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            user_id: member.id,
            name: "Old Spelling",
            credit_type: :finder
          },
          actor: poc
        )

      Accounts.set_user_credit!(
        member,
        %{credit_name: "Jonatan Männchen", credit_organization: "EEF"},
        actor: member
      )

      refreshed = Cases.refresh_case_credit!(credit, actor: poc)
      assert refreshed.name == "Jonatan Männchen"
      assert refreshed.organization == "EEF"
    end

    test "asks the provider again for a credit with no account", %{poc: poc, case: case_record} do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            name: "Old Spelling",
            organization: "Kept",
            credit_type: :finder,
            handles: [%{strategy: :github, username: "octocat"}]
          },
          actor: poc
        )

      refreshed = Cases.refresh_case_credit!(credit, actor: poc)
      assert refreshed.name == "The Octocat"
      assert refreshed.organization == "Kept"
      assert refreshed.user_id == nil
    end

    test "links the account that has since signed in with the handle", %{
      poc: poc,
      case: case_record
    } do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            name: "New Comer",
            credit_type: :finder,
            handles: [%{strategy: :github, username: "newcomer"}]
          },
          actor: poc
        )

      newcomer = Fixtures.register_user("newcomer")
      Accounts.set_user_credit!(newcomer, %{credit_name: "N. Comer"}, actor: newcomer)

      refreshed = Cases.refresh_case_credit!(credit, actor: poc)
      assert refreshed.user_id == newcomer.id
      assert refreshed.name == "N. Comer"
    end

    test "refuses a credit with neither an account nor a handle with a name", %{
      poc: poc,
      case: case_record
    } do
      credit =
        Cases.add_case_credit!(%{case_id: case_record.id, name: "Someone", credit_type: :finder},
          actor: poc
        )

      assert {:error, %Invalid{errors: [error]}} = Cases.refresh_case_credit(credit, actor: poc)
      assert error.field == :handles

      hermit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            name: "Hermit",
            credit_type: :finder,
            handles: [%{strategy: :github, username: "hermit"}]
          },
          actor: poc
        )

      assert {:error, %Invalid{}} = Cases.refresh_case_credit(hermit, actor: poc)
    end
  end

  describe "signing in" do
    test "claims the credits naming the handle, keeping their name", %{
      poc: poc,
      case: case_record
    } do
      credit =
        Cases.add_case_credit!(
          %{
            case_id: case_record.id,
            credit_type: :finder,
            name: "N. Comer",
            handles: [%{strategy: :github, username: "newcomer"}]
          },
          actor: poc
        )

      assert credit.user_id == nil

      newcomer = Fixtures.register_user("Newcomer")

      claimed = Ash.get!(CaseCredit, credit.id, actor: poc)
      assert claimed.user_id == newcomer.id
      assert claimed.name == "N. Comer"
    end

    test "claims a credit on a case that is no longer editable", %{poc: poc} do
      published = Fixtures.archived_case(:published, "Published", DateTime.utc_now())

      credit =
        Ash.Seed.seed!(CaseCredit, %{
          case_id: published.id,
          name: "N. Comer",
          credit_type: :finder,
          handles: [%{strategy: :github, username: "newcomer"}]
        })

      newcomer = Fixtures.register_user("newcomer")

      assert Ash.get!(CaseCredit, credit.id, actor: poc).user_id == newcomer.id
    end
  end

  describe "proposals" do
    test "an accepted credit proposal links the account and fills what it left blank", %{
      poc: poc,
      member: member,
      case: case_record
    } do
      Accounts.set_user_credit!(
        member,
        %{credit_name: "Jonatan Männchen", credit_organization: "EEF"},
        actor: member
      )

      proposal =
        Cases.propose_credit!(
          %{
            case_id: case_record.id,
            name: "Jonatan M.",
            credit_type: :coordinator,
            handles: [%{strategy: :github, username: "maennchen"}]
          },
          actor: poc
        )

      assert proposal.proposed_value["value"]["handles"] == [
               %{"strategy" => "github", "username" => "maennchen"}
             ]

      Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      [credit] = Cases.list_case_credits!(actor: poc, query: [filter: [case_id: case_record.id]])
      assert credit.user_id == member.id
      assert credit.name == "Jonatan M."
      assert credit.organization == "EEF"
      assert handles(credit) == [github: "maennchen"]
    end
  end

  describe "set proposals" do
    test "an accepted handle proposal on an existing credit links the account", %{
      poc: poc,
      member: member,
      case: case_record
    } do
      Accounts.set_user_credit!(member, %{credit_organization: "EEF"}, actor: member)

      credit =
        Cases.add_case_credit!(
          %{case_id: case_record.id, name: "Jonatan M.", credit_type: :finder},
          actor: poc
        )

      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :credit,
            target_id: credit.id,
            operation: :set,
            field_name: "handles",
            proposed_value: %{"value" => [%{"strategy" => "github", "username" => "maennchen"}]}
          },
          actor: poc
        )

      Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      linked = Ash.get!(CaseCredit, credit.id, authorize?: false)
      assert linked.user_id == member.id
      assert linked.name == "Jonatan M."
      assert linked.organization == "EEF"
      assert handles(linked) == [github: "maennchen"]
    end
  end

  describe "User :set_credit" do
    test "is the user's own to set", %{poc: poc, member: member} do
      assert {:error, %Forbidden{}} =
               Accounts.set_user_credit(member, %{credit_name: "Nope"}, actor: poc)

      user = Accounts.set_user_credit!(member, %{credit_name: "Jonatan Männchen"}, actor: member)

      assert Ash.load!(user, :credit_display_name, actor: member).credit_display_name ==
               "Jonatan Männchen"
    end
  end
end
