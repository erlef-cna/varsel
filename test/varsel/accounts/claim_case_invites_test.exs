# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.ClaimCaseInvitesTest do
  use Varsel.DataCase, async: false

  alias Varsel.Accounts.GitHub
  alias Varsel.Cases
  alias Varsel.Fixtures

  setup do
    Application.put_env(:varsel, :hex_stub_users, ["alice"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_users) end)

    Req.Test.stub(GitHub, fn conn ->
      login = conn.request_path |> Path.basename() |> URI.decode() |> String.downcase()

      if login in ["newcomer", "octocat"] do
        Req.Test.json(conn, %{"login" => login})
      else
        Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    poc = Fixtures.register_user("claim_poc", :poc)

    %{poc: poc, case: Fixtures.open_case(poc)}
  end

  defp assignees(case_record, actor) do
    case_record
    |> Ash.load!([assignments: [:user]], actor: actor)
    |> Map.fetch!(:assignments)
    |> Enum.map(& &1.user_id)
  end

  test "signing in for the first time claims the invite waiting for you", %{
    poc: poc,
    case: case_record
  } do
    Cases.invite_to_case!(
      %{case_id: case_record.id, strategy: :github, username: "newcomer"},
      actor: poc
    )

    newcomer = Fixtures.register_user("newcomer")

    assert newcomer.id in assignees(case_record, poc)
    assert Cases.list_case_invites!(actor: poc) == []
  end

  test "the match ignores casing", %{poc: poc, case: case_record} do
    Cases.invite_to_case!(
      %{case_id: case_record.id, strategy: :github, username: "OctoCat"},
      actor: poc
    )

    user = Fixtures.register_user("octocat")

    assert user.id in assignees(case_record, poc)
  end

  test "an invite for another provider is left alone", %{poc: poc, case: case_record} do
    Cases.invite_to_case!(
      %{case_id: case_record.id, strategy: :hex, username: "alice"},
      actor: poc
    )

    user = Fixtures.register_user("alice")

    refute user.id in assignees(case_record, poc)
    assert [_still_waiting] = Cases.list_case_invites!(actor: poc)
  end

  test "signing in with nothing waiting changes nothing", %{poc: poc, case: case_record} do
    user = Fixtures.register_user("newcomer")

    refute user.id in assignees(case_record, poc)
  end

  test "several invites across cases are all claimed at once", %{poc: poc, case: case_record} do
    second = Fixtures.open_case(poc, %{title: "Second"})

    for target <- [case_record, second] do
      Cases.invite_to_case!(
        %{case_id: target.id, strategy: :github, username: "newcomer"},
        actor: poc
      )
    end

    newcomer = Fixtures.register_user("newcomer")

    assert newcomer.id in assignees(case_record, poc)
    assert newcomer.id in assignees(second, poc)
    assert Cases.list_case_invites!(actor: poc) == []
  end

  test "an invite for someone already on the case is simply withdrawn", %{
    poc: poc,
    case: case_record
  } do
    sub = System.unique_integer([:positive])
    newcomer = Fixtures.sign_in_with_github("newcomer", sub)
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: newcomer.id}, actor: poc)

    Cases.invite_to_case!(
      %{case_id: case_record.id, strategy: :github, username: "newcomer"},
      actor: poc
    )

    assert %{} = Fixtures.sign_in_with_github("newcomer", sub)
    assert Cases.list_case_invites!(actor: poc) == []
  end
end
