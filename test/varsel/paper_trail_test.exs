# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.PaperTrailTest do
  use Varsel.DataCase, async: false

  alias Varsel.Accounts
  alias Varsel.CVE
  alias Varsel.Fixtures

  # The audit trail outlives the records it describes, so an address written
  # into it survives every deletion the privacy policy promises.
  test "no email address is written to the audit trail" do
    Fixtures.sign_in_with_hex("trail_user", 7101)

    CVE.submit_hex_vulnerability_report!(
      %{
        report_json: %{"report" => "x"},
        summary: "audited",
        participants: [
          %{
            role: :maintainer,
            strategy: :hex,
            username: "trail_other",
            email: "other@example.com"
          }
        ]
      },
      authorize?: false
    )

    [participant] = Ash.read!(CVE.ReportParticipant, authorize?: false)
    CVE.spend_report_participant!(participant, authorize?: false)

    versions =
      Enum.flat_map(
        [
          CVE.ReportParticipant.Version,
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
