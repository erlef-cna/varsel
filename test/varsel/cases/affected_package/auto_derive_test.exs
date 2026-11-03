# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.AutoDeriveTest do
  use Varsel.DataCase, async: true

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage.DeriveWorker
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/acme/auto_lib"
  @intro_sha String.duplicate("1", 40)
  @fix_sha String.duplicate("2", 40)

  setup do
    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.0.0", "v2.0.0"],
      {@repo, @fix_sha} => ["v2.0.0"]
    })

    poc = Fixtures.register_user("auto_derive_poc", :poc)
    case_record = Fixtures.open_case(poc)
    package = Fixtures.add_affected_package(poc, case_record, %{repo_url: @repo})

    %{poc: poc, case_record: case_record, package: package}
  end

  defp add_event(poc, package, attrs) do
    Cases.add_version_event!(
      Map.merge(%{case_id: package.case_id, affected_package_id: package.id}, attrs),
      actor: poc
    )
  end

  defp derive_jobs(package) do
    [worker: DeriveWorker]
    |> all_enqueued()
    |> Enum.filter(&(&1.args["primary_key"]["id"] == package.id))
  end

  defp run_derive_jobs do
    Oban.drain_queue(queue: :derivation, with_scheduled: true)
  end

  defp reload(package) do
    Ash.load!(package, [:derivation_state, :derivation_cache],
      authorize?: false,
      reuse_values?: false
    )
  end

  test "a fact edit schedules one derivation a few seconds out", %{poc: poc, package: package} do
    add_event(poc, package, %{event: :introduced, commit_sha: @intro_sha})
    add_event(poc, package, %{event: :fixed, commit_sha: @fix_sha})

    assert [job] = derive_jobs(package)
    assert job.state == "scheduled"
    assert DateTime.after?(job.scheduled_at, DateTime.utc_now())
  end

  test "the job derives with no actor and caches the facts", %{poc: poc, package: package} do
    add_event(poc, package, %{event: :introduced, commit_sha: @intro_sha})
    assert reload(package).derivation_state == :never

    assert %{success: 1, failure: 0} = run_derive_jobs()

    derived = reload(package)
    assert derived.derivation_state == :current

    assert derived.derivation_cache["channels"]
           |> Map.values()
           |> Enum.flat_map(& &1["versions"])
           |> Enum.any?()
  end

  test "removing a fact marks the derivation outdated", %{poc: poc, package: package} do
    event = add_event(poc, package, %{event: :fixed, commit_sha: @fix_sha})
    run_derive_jobs()
    assert reload(package).derivation_state == :current

    Cases.remove_version_event!(event, actor: poc)

    assert reload(package).derivation_state == :outdated
    assert [_job] = derive_jobs(package)
  end

  test "a write newer than the facts the derivation read keeps it outdated", %{package: package} do
    later = DateTime.shift(DateTime.utc_now(), minute: 1)
    package = Ash.Seed.update!(package, %{updated_at: later})

    Cases.derive_affected_package!(package, authorize?: false)

    assert reload(package).derivation_state == :outdated
  end

  test "a closed case is not derived", %{poc: poc, case_record: case_record, package: package} do
    add_event(poc, package, %{event: :introduced, commit_sha: @intro_sha})
    Ash.Seed.update!(case_record, %{state: :closed})

    assert %{success: 0} = run_derive_jobs()
    assert reload(package).derivation_state == :never
  end

  test ":derive and :note_facts_changed refuse direct callers", %{poc: poc, package: package} do
    supporter = Fixtures.register_user("auto_derive_roleless")

    for actor <- [nil, supporter, poc] do
      assert {:error, %Forbidden{}} =
               Cases.derive_affected_package(package, actor: actor)

      assert {:error, %Forbidden{}} =
               Cases.note_affected_package_facts_changed(package, actor: actor)
    end
  end
end
