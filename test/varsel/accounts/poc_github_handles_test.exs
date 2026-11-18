# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.PocGitHubHandlesTest do
  use Varsel.DataCase, async: true

  alias Varsel.Accounts
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("handles_poc_b", :poc)
    Fixtures.register_user("handles_poc_a", :poc)
    Fixtures.register_user("handles_supporter", :supporter)

    "handles_hex_poc"
    |> Fixtures.sign_in_with_hex(System.unique_integer([:positive]))
    |> Ash.update!(%{role: :poc}, action: :set_role, authorize?: false)

    reporter = Fixtures.register_user("handles_reporter")
    %{poc: poc, reporter: reporter}
  end

  defp handles(actor) do
    [actor: actor]
    |> Accounts.list_poc_github_handles!()
    |> Enum.map(&to_string(&1.username))
  end

  test "a role-less user gets the GitHub handles of the Points of Contact only", %{
    reporter: reporter
  } do
    assert handles(reporter) == ["handles_poc_a", "handles_poc_b"]
  end

  test "a row holds the handle and nothing else of the identity", %{reporter: reporter} do
    [identity | _] = Accounts.list_poc_github_handles!(actor: reporter)

    assert %Ash.NotLoaded{} = identity.email
    assert %Ash.NotLoaded{} = identity.encrypted_access_token
    assert %Ash.NotLoaded{} = identity.user_id
  end

  test "a POC gets the same list", %{poc: poc} do
    assert handles(poc) == ["handles_poc_a", "handles_poc_b"]
  end

  test "an anonymous caller is refused" do
    assert {:error, %Ash.Error.Forbidden{}} = Accounts.list_poc_github_handles(actor: nil)
  end
end
