# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.CheckDriftTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Cases.Case
  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.OsvRecord
  alias Varsel.CVE.OwnContainer
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/acme/acme_lib"
  @intro_sha String.duplicate("a", 40)
  @fix_sha String.duplicate("b", 40)
  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

  setup do
    poc = Fixtures.register_user("drift_poc_#{System.unique_integer([:positive])}", :poc)
    cve_id = "CVE-#{Date.utc_today().year}-#{40_000 + System.unique_integer([:positive])}"
    Fixtures.reserved_cve_record(cve_id)

    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.0.0", "v1.4.0"],
      {@repo, @fix_sha} => ["v1.4.0"]
    })

    Application.put_env(:varsel, :hex_stub_packages, ["acme_lib"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    Fixtures.seed_weakness(200, "Exposure of Sensitive Information")
    Fixtures.seed_attack_pattern(116, "Excavation")

    case_record =
      Fixtures.open_case(poc, %{
        title: "Information disclosure in acme_lib",
        description_md: "acme_lib leaks secrets to anyone who asks nicely.",
        cvss_v4: @vector
      })

    package =
      Fixtures.add_affected_package(poc, case_record, %{
        program_files: [%{path: "lib/acme_lib.ex"}]
      })

    Cases.add_package_channel!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        purl_type: :hex,
        name: "acme_lib"
      },
      actor: poc
    )

    for {event, sha} <- [introduced: @intro_sha, fixed: @fix_sha] do
      Cases.add_version_event!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          event: event,
          commit_sha: sha
        },
        actor: poc
      )
    end

    Cases.add_case_reference!(
      %{
        case_id: case_record.id,
        url: "https://github.com/acme/acme_lib/security/advisories/GHSA-xxxx-yyyy-zzzz",
        tags: ["vendor-advisory"],
        position: 0
      },
      actor: poc
    )

    Cases.add_case_weakness!(%{case_id: case_record.id, cwe_id: 200}, actor: poc)
    Cases.add_case_impact!(%{case_id: case_record.id, capec_id: 116}, actor: poc)

    Cases.add_case_credit!(
      %{case_id: case_record.id, name: "Ada Finder", credit_types: [:finder]},
      actor: poc
    )

    case_record = Cases.assign_case_cve_id!(case_record, %{}, actor: poc)
    {:ok, case_record} = Cases.refresh_case_derivation(case_record, actor: poc)

    %{poc: poc, case_record: publish_as_rendered(case_record, poc)}
  end

  # Puts the case in :published with its current render as the published
  # CVE and OSV records, as if MITRE took exactly what was sent.
  defp publish_as_rendered(case_record, poc) do
    %{preview: preview} = Ash.load!(case_record, [:preview], actor: poc)

    cve_json =
      put_in(preview.cve_record, ["cveMetadata", "datePublished"], "2026-07-15T00:00:00.000Z")

    cve_record = Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false)
    cve_record = Ash.Seed.update!(cve_record, %{state: :published, cve_json: cve_json})
    %{preview: preview} = Ash.load!(case_record, [:preview], actor: poc)

    Ash.Seed.seed!(OsvRecord, %{
      osv_id: get_in(cve_json, ["cveMetadata", "cveId"]),
      osv_json: preview.osv_record,
      content_hash: "seeded",
      modified_at: DateTime.utc_now(),
      synced_at: DateTime.utc_now(),
      cve_record_id: cve_record.id
    })

    Ash.Seed.update!(case_record, %{state: :published, published_at: DateTime.utc_now()})
  end

  defp run_check do
    AshOban.Test.schedule_and_run_triggers({Case, :check_drift}, scheduled_actions?: false)
  end

  defp reload(case_record), do: Ash.get!(Case, case_record.id, authorize?: false)

  defp checked?(case_record) do
    before = reload(case_record).drift_checked_at
    run_check()
    reload(case_record).drift_checked_at not in [nil, before]
  end

  test "a published case whose render matches its records is in sync", %{case_record: case_record} do
    assert checked?(case_record)

    checked = reload(case_record)
    assert checked.record_drift == :in_sync
    assert %DateTime{} = checked.drift_checked_at
  end

  test "a changed published record is drift", %{case_record: case_record} do
    cve_record = Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false)

    stale_json =
      OwnContainer.put(cve_record.cve_json, %{
        OwnContainer.get(cve_record.cve_json)
        | "title" => "An older rendering"
      })

    Ash.Seed.update!(cve_record, %{cve_json: stale_json})

    assert checked?(case_record)
    assert reload(case_record).record_drift == :drifted
  end

  test "a date_public before MITRE's publication is not drift", %{case_record: case_record} do
    case_record = Ash.Seed.update!(case_record, %{date_public: ~U[2026-01-15 09:30:00Z]})
    cve_record = Ash.get!(CveRecord, case_record.cve_record_id, authorize?: false)

    container =
      Map.put(OwnContainer.get(cve_record.cve_json), "datePublic", "2026-01-15T09:30:00.000Z")

    Ash.Seed.update!(cve_record, %{cve_json: OwnContainer.put(cve_record.cve_json, container)})

    assert checked?(case_record)
    assert reload(case_record).record_drift == :in_sync
  end

  test "a render with publish blockers is blocked", %{case_record: case_record} do
    Ash.Seed.update!(case_record, %{cvss_v4: nil})

    assert checked?(case_record)
    assert reload(case_record).record_drift == :blocked
  end

  test "the check fetches each package repository first", %{case_record: case_record} do
    run_check()
    assert @repo in StubGitBackend.refreshed_repos()
    assert reload(case_record).record_drift == :in_sync
  end

  describe "schedule" do
    defp due?(published_days_ago, checked_days_ago, case_record) do
      now = DateTime.utc_now()

      Ash.Seed.update!(case_record, %{
        published_at: DateTime.shift(now, day: -published_days_ago),
        drift_checked_at: DateTime.shift(now, day: -checked_days_ago)
      })

      checked?(case_record)
    end

    test "a case published this month is checked daily", %{case_record: case_record} do
      refute due?(10, 0, case_record)
      assert due?(10, 2, case_record)
    end

    test "a case published this year is checked weekly", %{case_record: case_record} do
      refute due?(100, 2, case_record)
      assert due?(100, 8, case_record)
    end

    test "an older case is checked monthly", %{case_record: case_record} do
      refute due?(400, 8, case_record)
      assert due?(400, 31, case_record)
    end

    test "a case outside :published is never checked", %{case_record: case_record} do
      Ash.Seed.update!(case_record, %{state: :draft, drift_checked_at: nil})
      refute checked?(case_record)
    end
  end

  describe "recheck" do
    setup %{case_record: case_record} do
      run_check()
      %{case_record: reload(case_record)}
    end

    test "a POC queues one case at once", %{poc: poc, case_record: case_record} do
      rechecked = Cases.recheck_case_drift!(case_record, actor: poc)
      assert rechecked.drift_checked_at == nil
      assert_enqueued(worker: Varsel.Cases.Case.CheckDriftWorker)
    end

    test "a POC queues every published case at once", %{poc: poc, case_record: case_record} do
      assert :ok = Cases.recheck_published_case_drift!(actor: poc)
      assert reload(case_record).drift_checked_at == nil
    end

    test "nobody below POC may recheck", %{case_record: case_record} do
      supporter =
        Fixtures.register_user("drift_sup_#{System.unique_integer([:positive])}", :supporter)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id},
        authorize?: false
      )

      nobody = Fixtures.register_user("drift_nobody_#{System.unique_integer([:positive])}")

      for actor <- [nil, nobody, supporter] do
        refute Cases.can_recheck_case_drift?(actor, case_record)
        refute Cases.can_recheck_published_case_drift?(actor)
        assert {:error, %Forbidden{}} = Cases.recheck_published_case_drift(actor: actor)
      end
    end

    test "only a published case may be rechecked", %{poc: poc, case_record: case_record} do
      draft = Ash.Seed.update!(case_record, %{state: :draft})
      refute Cases.can_recheck_case_drift?(poc, draft)
    end
  end

  test "only a POC may list the out-of-date cases", %{poc: poc, case_record: case_record} do
    Ash.Seed.update!(case_record, %{record_drift: :drifted, drift_checked_at: DateTime.utc_now()})

    supporter =
      Fixtures.register_user("drift_lister_#{System.unique_integer([:positive])}", :supporter)

    nobody = Fixtures.register_user("drift_nolister_#{System.unique_integer([:positive])}")

    assert [%{id: id}] = Cases.list_drifted_cases!(actor: poc)
    assert id == case_record.id

    for actor <- [nil, nobody, supporter] do
      refute Cases.can_list_drifted_cases?(actor)
      assert {:error, %Forbidden{}} = Cases.list_drifted_cases(actor: actor)
    end
  end

  test "no request may run the check itself", %{poc: poc, case_record: case_record} do
    refute Cases.can_check_case_drift?(poc, case_record)
  end

  test "the drift fields are for POCs only", %{poc: poc, case_record: case_record} do
    run_check()

    supporter =
      Fixtures.register_user("drift_reader_#{System.unique_integer([:positive])}", :supporter)

    Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, authorize?: false)

    assert Cases.get_case!(case_record.id, actor: poc).record_drift == :in_sync

    seen = Cases.get_case!(case_record.id, actor: supporter)
    assert %Ash.ForbiddenField{} = seen.record_drift
    assert %Ash.ForbiddenField{} = seen.drift_checked_at
  end
end
