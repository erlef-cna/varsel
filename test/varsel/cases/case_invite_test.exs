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
  alias Varsel.HexPm

  setup do
    Req.Test.stub(HexPm, fn conn ->
      case conn.path_info do
        ["api", "users", "alice", "contact"] ->
          Req.Test.json(conn, %{
            "username" => "alice",
            "name" => "alice",
            "email" => "alice@example.com"
          })

        ["api", "users", "bob", "contact"] ->
          Req.Test.json(conn, %{"username" => "bob", "name" => "bob"})

        _unknown ->
          Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    Req.Test.stub(GitHub, fn conn ->
      case conn.request_path |> Path.basename() |> URI.decode() |> String.downcase() do
        "octocat" ->
          Req.Test.json(conn, %{"login" => "octocat", "email" => "octocat@example.com"})

        "hermit" ->
          Req.Test.json(conn, %{"login" => "hermit", "email" => nil})

        _unknown ->
          Plug.Conn.send_resp(conn, 404, "{}")
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

  describe ":invite email" do
    setup do
      original_key = Application.get_env(:varsel, :hex_signing_key)

      on_exit(fn -> Application.put_env(:varsel, :hex_signing_key, original_key) end)

      :ok
    end

    defp invite!(case_record, poc, attrs) do
      Cases.invite_to_case!(Map.merge(%{case_id: case_record.id}, attrs), actor: poc)
    end

    defp invite(case_record, poc, attrs) do
      Cases.invite_to_case(Map.merge(%{case_id: case_record.id}, attrs), actor: poc)
    end

    defp sent_emails(acc \\ []) do
      receive do
        {:email, email} -> sent_emails([email | acc])
      after
        0 -> Enum.reverse(acc)
      end
    end

    test "goes to the public address on the GitHub profile", %{poc: poc, case: case_record} do
      invite = invite!(case_record, poc, %{strategy: :github, username: "octocat"})

      assert to_string(invite.email) == "octocat@example.com"
      assert invite.email_status == :pending
    end

    test "a GitHub profile without a public address needs one from the inviter", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{strategy: :github, username: "hermit"})

      assert Exception.message(error) =~ "GitHub lists no address"

      invite =
        invite!(case_record, poc, %{
          strategy: :github,
          username: "hermit",
          email: "hermit@example.org"
        })

      assert to_string(invite.email) == "hermit@example.org"
      assert invite.email_status == :pending
    end

    test "an inviter's address must match the public one when the profile has it", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{
                 strategy: :github,
                 username: "octocat",
                 email: "other@example.com"
               })

      assert Exception.message(error) =~ "does not match"

      invite =
        invite!(case_record, poc, %{
          strategy: :github,
          username: "octocat",
          email: "OctoCat@Example.com"
        })

      assert to_string(invite.email) == "octocat@example.com"
    end

    test "the inviter can skip the email when the profile lists no address", %{
      poc: poc,
      case: case_record
    } do
      invite =
        invite!(case_record, poc, %{strategy: :github, username: "hermit", skip_email: true})

      assert invite.email == nil
      assert invite.email_status == :skipped
    end

    test "the email cannot be skipped when the profile lists an address", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{
                 strategy: :github,
                 username: "octocat",
                 skip_email: true
               })

      assert Exception.message(error) =~ "cannot be skipped"
    end

    test "an email and a skip together are refused", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{
                 strategy: :github,
                 username: "hermit",
                 email: "hermit@example.org",
                 skip_email: true
               })

      assert Exception.message(error) =~ "together with an email"
    end

    test "a hex.pm email cannot be skipped when hex.pm holds an address", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{strategy: :hex, username: "alice", skip_email: true})

      assert Exception.message(error) =~ "cannot be skipped"
    end

    test "comes from hex.pm for a hex.pm handle", %{poc: poc, case: case_record} do
      invite = invite!(case_record, poc, %{strategy: :hex, username: "alice"})

      assert to_string(invite.email) == "alice@example.com"
      assert invite.email_status == :pending
    end

    test "a hex.pm account without a verified address needs one from the inviter", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{strategy: :hex, username: "bob"})

      assert Exception.message(error) =~ "hex.pm lists no address"

      invite =
        invite!(case_record, poc, %{strategy: :hex, username: "bob", email: "bob@example.org"})

      assert to_string(invite.email) == "bob@example.org"
      assert invite.email_status == :pending

      other_case = Fixtures.open_case(poc)
      invite = invite!(other_case, poc, %{strategy: :hex, username: "bob", skip_email: true})
      assert invite.email_status == :skipped
    end

    test "an inviter's address must match the one hex.pm holds", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{
                 strategy: :hex,
                 username: "alice",
                 email: "other@example.com"
               })

      assert Exception.message(error) =~ "does not match"

      invite =
        invite!(case_record, poc, %{strategy: :hex, username: "alice", email: "Alice@example.com"})

      assert to_string(invite.email) == "alice@example.com"
    end

    test "without a signing key a hex.pm invite falls back to the public profile", %{
      poc: poc,
      case: case_record
    } do
      Application.delete_env(:varsel, :hex_signing_key)
      Application.put_env(:varsel, :hex_stub_users, ["alice"])
      on_exit(fn -> Application.delete_env(:varsel, :hex_stub_users) end)

      assert {:error, %Invalid{} = error} =
               invite(case_record, poc, %{strategy: :hex, username: "AliCe"})

      assert Exception.message(error) =~ "hex.pm lists no address"

      invite =
        invite!(case_record, poc, %{strategy: :hex, username: "AliCe", email: "alice@example.org"})

      assert to_string(invite.username) == "alice"
      assert to_string(invite.email) == "alice@example.org"
      assert invite.email_status == :pending
    end

    test "one address is emailed once per case", %{poc: poc, case: case_record} do
      first = invite!(case_record, poc, %{strategy: :hex, username: "alice"})

      second =
        invite!(case_record, poc, %{
          strategy: :github,
          username: "hermit",
          email: "Alice@example.com"
        })

      assert first.email_status == :pending
      assert second.email_status == :duplicate
      assert to_string(second.email) == "Alice@example.com"

      other_case = Fixtures.open_case(poc)

      assert invite!(other_case, poc, %{strategy: :hex, username: "alice"}).email_status ==
               :pending
    end

    test "only a POC reads the address", %{poc: poc, case: case_record} do
      supporter = Fixtures.register_user("invite_email_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      invite!(case_record, poc, %{strategy: :github, username: "octocat"})

      assert [%{email: %Ash.CiString{}}] = Cases.list_case_invites!(actor: poc)
      assert [%{email: %Ash.ForbiddenField{}}] = Cases.list_case_invites!(actor: supporter)
    end

    test "the queued email goes out with a sign-in link and no case content", %{
      poc: poc,
      case: case_record
    } do
      invite = invite!(case_record, poc, %{strategy: :github, username: "octocat"})

      Oban.drain_queue(queue: :default, with_recursion: true)

      assert [email] = sent_emails()
      assert email.to == [{"", "octocat@example.com"}]
      assert email.subject == "EEF CNA: you are invited to a case"
      assert email.text_body =~ ~s(GitHub account "octocat")
      assert email.text_body =~ "/sign-in?return_to=%2Fcases%2F#{case_record.id}"
      refute email.text_body =~ case_record.title

      assert [%{email_status: :sent, emailed_at: %DateTime{}}] =
               Cases.list_case_invites!(actor: poc)

      assert invite.email_status == :pending
    end

    test "an invite without an address sends nothing", %{poc: poc, case: case_record} do
      invite!(case_record, poc, %{strategy: :github, username: "hermit", skip_email: true})
      invite!(case_record, poc, %{strategy: :hex, username: "bob", skip_email: true})

      Oban.drain_queue(queue: :default, with_recursion: true)

      assert sent_emails() == []
    end

    test "a withdrawn invite sends nothing", %{poc: poc, case: case_record} do
      invite = invite!(case_record, poc, %{strategy: :github, username: "octocat"})
      Cases.withdraw_case_invite!(invite, actor: poc)

      Oban.drain_queue(queue: :default, with_recursion: true)

      assert sent_emails() == []
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
      assert invite.email_status == :pending
    end

    test "passes the inviter's address and the skip through to the invite", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, %Invalid{}} =
               Cases.grant_case_access(case_record, :github, "hermit", actor: poc)

      assert {:ok, _} =
               Cases.grant_case_access(
                 case_record,
                 :github,
                 "hermit",
                 %{email: "hermit@example.org"},
                 actor: poc
               )

      other_case = Fixtures.open_case(poc)

      assert {:ok, _} =
               Cases.grant_case_access(other_case, :github, "hermit", %{skip_email: true}, actor: poc)

      assert [%{email_status: :pending}, %{email_status: :skipped}] =
               Enum.sort_by(Cases.list_case_invites!(actor: poc), & &1.inserted_at, DateTime)
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
