# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PublicationTest do
  @moduledoc """
  End-to-end publish flow: propose → accept → approve → publish (handoff to
  the CVE record + MITRE double) → mark_published, plus the amendment loop.
  """

  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.CVE.CveRecord
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/acme/acme_lib"
  @fix_sha String.duplicate("b", 40)
  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

  setup do
    poc = Fixtures.register_user("publication_poc", :poc)
    year = Date.utc_today().year
    cve_id = "CVE-#{year}-31337"
    Fixtures.reserved_cve_record(cve_id)

    StubGitBackend.stub_tags(%{{@repo, @fix_sha} => ["v1.4.0"]})
    Application.put_env(:varsel, :hex_stub_packages, ["acme_lib"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    case_record =
      Fixtures.open_case(poc, %{
        title: "Information disclosure in acme_lib",
        description_md: "acme_lib leaks secrets to anyone who asks nicely.",
        cvss_v4: @vector
      })

    package =
      Fixtures.add_affected_package(poc, case_record, %{program_files: ["lib/acme_lib.ex"]})

    Cases.add_package_channel!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        channel_type: :hex,
        package_name: "acme_lib"
      },
      actor: poc
    )

    Cases.add_package_channel!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        channel_type: :git,
        package_name: "acme/acme_lib",
        position: 1
      },
      actor: poc
    )

    Cases.add_version_event!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        event: :introduced,
        version: "0"
      },
      actor: poc
    )

    Cases.add_version_event!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        event: :fixed,
        commit_sha: @fix_sha
      },
      actor: poc
    )

    Cases.add_case_reference!(
      %{
        case_id: case_record.id,
        url: "https://github.com/acme/acme_lib/security/advisories/GHSA-xxxx-yyyy-zzzz",
        tags: ["vendor-advisory"],
        position: 0
      },
      actor: poc
    )

    case_record = Cases.assign_case_cve_id!(case_record, %{}, actor: poc)

    %{poc: poc, case: case_record, cve_id: cve_id}
  end

  defp stub_mitre_accepting(cve_id) do
    Req.Test.stub(Varsel.CVE.MitreCveApi, fn conn ->
      # POST/PUT accept the container; GET returns the published record.
      Req.Test.json(conn, %{
        "dataType" => "CVE_RECORD",
        "dataVersion" => "5.2",
        "cveMetadata" => %{
          "cveId" => cve_id,
          "state" => "PUBLISHED",
          "assignerShortName" => "EEF",
          "datePublished" => "2026-07-15T00:00:00.000Z",
          "dateUpdated" => "2026-07-15T00:00:00.000Z"
        },
        "containers" => %{"cna" => %{"title" => "Information disclosure in acme_lib"}}
      })
    end)
  end

  test "publish blocks while the case is not approved", %{poc: poc, case: case_record} do
    assert {:error, error} = Cases.publish_case(case_record, actor: poc)
    assert Exception.message(error) =~ "no matching transition"
  end

  test "the full publish handoff", %{poc: poc, case: case_record, cve_id: cve_id} do
    stub_mitre_accepting(cve_id)

    case_record = Cases.request_case_review!(case_record, actor: poc)
    case_record = Cases.approve_case!(case_record, actor: poc)
    case_record = Cases.publish_case!(case_record, actor: poc)

    assert case_record.state == :publishing

    # The handoff moved the CVE record to :publishing with the rendered record.
    cve_record = Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false)
    assert cve_record.state == :publishing

    assert get_in(cve_record.cve_json, ["containers", "cna", "title"]) ==
             "Information disclosure in acme_lib"

    assert [_hex, _git] = get_in(cve_record.cve_json, ["containers", "cna", "affected"])

    # The Oban publish worker pushes to MITRE; then the case trigger completes.
    assert %{success: publish_successes} =
             AshOban.Test.schedule_and_run_triggers({CveRecord, :publish},
               scheduled_actions?: false
             )

    assert publish_successes >= 1
    assert Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false).state == :published

    assert %{success: mark_successes} =
             AshOban.Test.schedule_and_run_triggers({Cases.Case, :mark_published},
               scheduled_actions?: false
             )

    assert mark_successes >= 1

    case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)
    assert case_record.state == :published
    assert case_record.published_at
  end

  test "publish blocks on render blockers", %{poc: poc, case: case_record} do
    case_record = Cases.edit_case!(case_record, %{cvss_v4: nil}, actor: poc)
    case_record = Cases.request_case_review!(case_record, actor: poc)
    case_record = Cases.approve_case!(case_record, actor: poc)

    assert {:error, error} = Cases.publish_case(case_record, actor: poc)
    assert Exception.message(error) =~ "CVSS v4 vector is missing"

    # The case stayed approved; nothing was handed to the CVE record.
    assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :approved
    assert Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false).state == :draft
  end

  test "amendment: reopen a published case and publish an update", %{
    poc: poc,
    case: case_record,
    cve_id: cve_id
  } do
    stub_mitre_accepting(cve_id)

    case_record = Cases.request_case_review!(case_record, actor: poc)
    case_record = Cases.approve_case!(case_record, actor: poc)
    case_record = Cases.publish_case!(case_record, actor: poc)

    AshOban.Test.schedule_and_run_triggers({CveRecord, :publish}, scheduled_actions?: false)

    AshOban.Test.schedule_and_run_triggers({Cases.Case, :mark_published},
      scheduled_actions?: false
    )

    case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)
    assert case_record.state == :published

    case_record = Cases.reopen_case!(case_record, actor: poc)
    case_record = Cases.edit_case!(case_record, %{title: "Worse than we thought"}, actor: poc)
    case_record = Cases.request_case_review!(case_record, actor: poc)
    case_record = Cases.approve_case!(case_record, actor: poc)
    case_record = Cases.publish_case!(case_record, actor: poc)

    assert case_record.state == :publishing

    # The amendment went through CveRecord.update -> :pending_update.
    cve_record = Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false)
    assert cve_record.state == :pending_update
    assert get_in(cve_record.cve_json, ["containers", "cna", "title"]) == "Worse than we thought"
  end

  test "render_preview reports validation and blockers without publishing", %{
    poc: poc,
    case: case_record
  } do
    preview = Cases.render_case_preview!(%{id: case_record.id}, actor: poc)

    assert preview["blockers"] == []
    assert preview["validation"][:valid] == true
    assert get_in(preview, ["cna", "providerMetadata", "shortName"]) == "EEF"
    assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :draft
  end
end
