# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.ClaimReportParticipantsTest do
  use Varsel.DataCase, async: false

  alias Varsel.CVE
  alias Varsel.Fixtures

  defp report_naming(username, role \\ :reporter) do
    CVE.submit_hex_vulnerability_report!(
      %{
        report_json: %{"package" => "acme"},
        summary: "Unsafe parsing",
        participants: [
          %{role: role, strategy: :hex, username: username, email: "#{username}@example.com"}
        ]
      },
      authorize?: false
    )
  end

  defp participants(actor) do
    CVE.list_report_participants!(actor: actor)
  end

  test "signing in with the named hex handle claims the participant" do
    poc = Fixtures.register_user("claim_poc", :poc)
    report_naming("reporter")

    user = Fixtures.sign_in_with_hex("reporter", 4001)

    assert [participant] = participants(poc)
    assert participant.user_id == user.id
    assert participant.report_id
  end

  test "the handle matches regardless of how the provider spells it" do
    poc = Fixtures.register_user("claim_case_poc", :poc)
    report_naming("RePorTer")

    user = Fixtures.sign_in_with_hex("reporter", 4002)

    assert [%{user_id: user_id}] = participants(poc)
    assert user_id == user.id
  end

  test "a GitHub sign-in does not claim a hex participant" do
    poc = Fixtures.register_user("claim_gh_poc", :poc)
    report_naming("reporter")

    Fixtures.sign_in_with_github("reporter", 4003)

    assert [%{user_id: nil}] = participants(poc)
  end

  test "an unrelated handle claims nothing" do
    poc = Fixtures.register_user("claim_other_poc", :poc)
    report_naming("reporter")

    Fixtures.sign_in_with_hex("someone-else", 4004)

    assert [%{user_id: nil}] = participants(poc)
  end

  test "maintainers are claimed the same way" do
    poc = Fixtures.register_user("claim_maintainer_poc", :poc)
    report_naming("maintainer", :maintainer)

    user = Fixtures.sign_in_with_hex("maintainer", 4005)

    assert [%{user_id: user_id, role: :maintainer}] = participants(poc)
    assert user_id == user.id
  end

  test "the row survives the claim rather than being consumed" do
    poc = Fixtures.register_user("claim_survives_poc", :poc)
    report_naming("reporter")

    Fixtures.sign_in_with_hex("reporter", 4006)

    assert [%{email: "reporter@example.com"}] = participants(poc)
  end

  test "a second sign-in with the same handle is harmless" do
    poc = Fixtures.register_user("claim_twice_poc", :poc)
    report_naming("reporter")

    user = Fixtures.sign_in_with_hex("reporter", 4007)
    Fixtures.sign_in_with_hex("reporter", 4007)

    assert [%{user_id: user_id}] = participants(poc)
    assert user_id == user.id
  end
end
