# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.PaperTrailTest do
  use Varsel.DataCase, async: true

  alias Varsel.Accounts
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.HexPm
  alias Varsel.Service

  # The audit trail outlives the records it describes, so an address written
  # into it survives every deletion the privacy policy promises.
  test "no email address is written to the audit trail" do
    Req.Test.stub(HexPm, fn conn ->
      ["api", "users", username, "contact"] = conn.path_info

      Req.Test.json(conn, %{
        "username" => username,
        "name" => username,
        "email" => "#{username}@example.com"
      })
    end)

    Fixtures.sign_in_with_hex("trail_user", 7101)

    Cases.submit_hex_vulnerability_report!(
      %{
        report_json: %{"report" => "x"},
        summary: "audited",
        reporter_username: "trail_user",
        reporter_email: "trail_user@example.com",
        maintainers: [%{username: "trail_other", email: "trail_other@example.com"}]
      },
      actor: Service.hexpm_intake()
    )

    versions =
      Enum.flat_map(
        [
          Cases.VulnerabilityReport.Version,
          Cases.CaseInvite.Version,
          Accounts.UserIdentity.Version,
          Accounts.User.Version
        ],
        &Ash.read!(&1, authorize?: false)
      )

    assert versions != []

    for version <- versions, {field, value} <- version.changes do
      refute String.ends_with?(field, "email"),
             "#{inspect(version.__struct__)} versions #{field}"

      refute is_binary(value) and String.contains?(value, "@"),
             "#{inspect(version.__struct__)} wrote an address into #{field}"
    end
  end
end
