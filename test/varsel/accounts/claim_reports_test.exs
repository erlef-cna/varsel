# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.ClaimReportsTest do
  use Varsel.DataCase, async: true

  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.HexPm
  alias Varsel.Service

  setup do
    Req.Test.stub(HexPm, fn conn ->
      ["api", "users", username, "contact"] = conn.path_info

      Req.Test.json(conn, %{
        "username" => String.downcase(username),
        "name" => username,
        "email" => "#{username}@example.com"
      })
    end)

    :ok
  end

  defp report_naming(reporter, maintainers \\ []) do
    %{vulnerability_reports: [report]} =
      Cases.submit_hex_vulnerability_report!(
        %{
          report_json: %{"package" => "acme"},
          summary: "Unsafe parsing",
          reporter_username: reporter,
          maintainers: Enum.map(maintainers, &%{username: &1})
        },
        actor: Service.hexpm_intake()
      )

    report
  end

  defp reporter_id(report), do: Ash.reload!(report, authorize?: false).reporter_id

  test "signing in with the reporter's hex handle hands over the report" do
    report = report_naming("claim_reporter")

    user = Fixtures.sign_in_with_hex("claim_reporter", 4001)

    # What the sign-in link is for: the reporter can now read the report it
    # sent them to.
    assert reporter_id(report) == user.id
    assert [%{id: id}] = Cases.list_vulnerability_reports!(actor: user)
    assert id == report.id
  end

  test "an account that already holds the handle takes the report at intake" do
    user = Fixtures.sign_in_with_hex("claim_known", 4002)

    assert report_naming("claim_known").reporter_id == user.id
  end

  test "the same handle at another provider is not the reporter" do
    Fixtures.sign_in_with_github("claim_crossed", 4003)

    assert is_nil(report_naming("claim_crossed").reporter_id)
  end

  test "a report that already has a reporter is not taken over" do
    first = Fixtures.register_user("claim_incumbent")
    report = report_naming("claim_reporter")
    Ash.Seed.update!(report, %{reporter_id: first.id})

    Fixtures.sign_in_with_hex("claim_reporter", 4004)

    assert reporter_id(report) == first.id
  end

  test "a maintainer signing in does not become the reporter" do
    report = report_naming("claim_reporter", ["claim_maintainer"])

    Fixtures.sign_in_with_hex("claim_maintainer", 4005)

    assert is_nil(reporter_id(report))
  end

  test "the handle matches regardless of how the provider spells it" do
    report = report_naming("Claim_RePorTer")

    user = Fixtures.sign_in_with_hex("claim_reporter", 4006)

    assert reporter_id(report) == user.id
  end

  test "a GitHub sign-in does not claim a hex report" do
    report = report_naming("claim_reporter")

    Fixtures.sign_in_with_github("claim_reporter", 4007)

    assert is_nil(reporter_id(report))
  end

  test "a second sign-in with the same handle is harmless" do
    report = report_naming("claim_reporter")

    user = Fixtures.sign_in_with_hex("claim_reporter", 4008)
    Fixtures.sign_in_with_hex("claim_reporter", 4008)

    assert reporter_id(report) == user.id
  end
end
