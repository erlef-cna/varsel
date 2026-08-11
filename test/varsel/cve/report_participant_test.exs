# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.ReportParticipantTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.CVE
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("participant_poc", :poc)

    report =
      CVE.submit_hex_vulnerability_report!(
        %{
          report_json: %{"package" => "acme", "description" => "Bad."},
          summary: "Unsafe parsing",
          participants: [
            %{
              role: :reporter,
              strategy: :hex,
              username: "reporter",
              name: "Reporter",
              email: "reporter@example.com"
            },
            %{
              role: :maintainer,
              strategy: :hex,
              username: "maintainer",
              name: "Maintainer",
              email: "maintainer@example.com"
            }
          ]
        },
        authorize?: false
      )

    %{poc: poc, report: report}
  end

  test "a POC sees everyone the intake named", %{poc: poc} do
    participants = CVE.list_report_participants!(actor: poc)

    assert MapSet.new(participants, & &1.role) == MapSet.new([:reporter, :maintainer])
  end

  describe "confidentiality" do
    test "the reporter cannot read participants, including their own row", %{report: report} do
      reporter = Fixtures.register_user("participant_reporter")
      Ash.Seed.update!(report, %{reporter_id: reporter.id})

      assert CVE.list_report_participants!(actor: reporter) == []
    end

    test "a supporter cannot read participants" do
      supporter = Fixtures.register_user("participant_supporter", :supporter)

      assert CVE.list_report_participants!(actor: supporter) == []
    end

    test "an anonymous caller cannot read participants" do
      assert CVE.list_report_participants!(actor: nil) == []
    end

    test "loading them through the report yields nothing for a non-POC", %{
      poc: poc,
      report: report
    } do
      supporter = Fixtures.register_user("participant_loader", :supporter)

      assert %{participants: []} = Ash.load!(report, [:participants], actor: supporter)
      assert %{participants: [_, _]} = Ash.load!(report, [:participants], actor: poc)
    end

    # The intake action answers to the sending system's actor, not to the
    # route in front of it, so a second caller reaching it gains nothing.
    test "the intake action refuses anyone but the sending system" do
      poc = Fixtures.register_user("intake_poc_denied", :poc)

      attrs = %{
        report_json: %{"package" => "acme"},
        summary: "Smuggled",
        participants: [%{role: :maintainer, strategy: :hex, username: "mallory"}]
      }

      assert {:error, %Forbidden{}} = CVE.submit_hex_vulnerability_report(attrs, actor: poc)
      assert {:error, %Forbidden{}} = CVE.submit_hex_vulnerability_report(attrs, actor: nil)
    end

    test "the actor-facing intake cannot carry participants" do
      reporter = Fixtures.register_user("participant_submitter")

      assert {:error, error} =
               CVE.submit_vulnerability_report(
                 %{
                   report_json: %{"report" => "Bad."},
                   summary: "Smuggled",
                   confirms_criteria: true,
                   confirms_in_scope: true,
                   participants: [
                     %{role: :maintainer, strategy: :hex, username: "mallory"}
                   ]
                 },
                 actor: reporter
               )

      assert Exception.message(error) =~ "participants"
    end

    test "a non-POC cannot record a participant", %{report: report} do
      supporter = Fixtures.register_user("participant_writer", :supporter)

      assert {:error, %Forbidden{}} =
               CVE.record_report_participant(
                 %{
                   report_id: report.id,
                   role: :maintainer,
                   strategy: :hex,
                   username: "mallory"
                 },
                 actor: supporter
               )
    end
  end

  test "the same handle cannot be recorded twice in one role", %{poc: poc, report: report} do
    assert {:error, error} =
             CVE.record_report_participant(
               %{
                 report_id: report.id,
                 role: :maintainer,
                 strategy: :hex,
                 username: "Maintainer"
               },
               actor: poc
             )

    assert Exception.message(error) =~ "already been taken"
  end
end
