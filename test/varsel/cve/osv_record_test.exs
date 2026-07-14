# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.OsvRecordTest do
  use Varsel.DataCase, async: false

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.OsvRecord

  @cve_id "CVE-2025-12345"

  setup do
    Application.put_env(:varsel, :hex_stub_packages, %{
      "test_lib" => ["1.0.0", "1.2.2", "1.2.3", "2.0.0"]
    })

    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)
  end

  defp cve_json(overrides \\ %{}) do
    affected =
      Map.get(overrides, :affected, [
        %{
          "vendor" => "Erlang Ecosystem Foundation",
          "product" => "test_lib",
          "packageURL" => "pkg:hex/test_lib",
          "defaultStatus" => "unaffected",
          "versions" => [
            %{
              "version" => "0",
              "lessThan" => Map.get(overrides, :less_than, "1.2.3"),
              "status" => "affected",
              "versionType" => "semver"
            }
          ]
        }
      ])

    %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => Map.get(overrides, :cve_id, @cve_id),
        "state" => "PUBLISHED",
        "datePublished" => "2026-04-27T12:00:00.000Z",
        "dateUpdated" => Map.get(overrides, :date_updated, "2026-04-27T12:00:00.000Z")
      },
      "containers" => %{
        "cna" => %{
          "title" => Map.get(overrides, :title, "Test vulnerability"),
          "descriptions" => [%{"lang" => "en", "value" => "A test vulnerability."}],
          "affected" => affected,
          "references" => [%{"url" => "https://example.com/advisory"}]
        }
      }
    }
  end

  defp import_cve(cve_json) do
    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  defp create_missing do
    OsvRecord
    |> Ash.ActionInput.for_action(:create_missing, %{})
    |> Ash.run_action!(authorize?: false)
  end

  defp run_sync_triggers do
    AshOban.Test.schedule_and_run_triggers({OsvRecord, :sync})
  end

  defp get_osv(osv_id \\ "EEF-#{@cve_id}") do
    OsvRecord
    |> Ash.Query.for_read(:get, %{osv_id: osv_id})
    |> Ash.read_one!(authorize?: false)
  end

  defp backdate_sync(hours) do
    stale = DateTime.add(DateTime.utc_now(), -hours, :hour)
    Varsel.Repo.update_all("osv_records", set: [synced_at: stale])
  end

  describe "create_missing" do
    test "creates OSV records for published convertible CVE records" do
      cve_record = import_cve(cve_json())

      create_missing()

      osv = get_osv()
      assert osv.cve_record_id == cve_record.id
      assert osv.content_hash
      assert osv.withdrawn_at == nil
      assert DateTime.compare(osv.modified_at, osv.synced_at) == :eq

      assert osv.osv_json["id"] == "EEF-#{@cve_id}"
      assert osv.osv_json["modified"] == DateTime.to_iso8601(osv.modified_at)
      assert osv.osv_json["summary"] == "Test vulnerability"

      # affected hex.pm versions are enumerated from the stubbed repository
      assert [%{"versions" => ["1.0.0", "1.2.2"]}] = osv.osv_json["affected"]
    end

    test "is idempotent" do
      import_cve(cve_json())

      create_missing()
      osv = get_osv()

      create_missing()
      assert get_osv().modified_at == osv.modified_at
      assert Ash.count!(OsvRecord, authorize?: false) == 1
    end

    test "a failing hex.pm lookup does not block other records" do
      import_cve(cve_json())

      import_cve(
        cve_json(%{
          cve_id: "CVE-2025-66666",
          affected: [
            %{
              "vendor" => "Acme",
              "product" => "gone_lib",
              "packageURL" => "pkg:hex/gone_lib",
              "defaultStatus" => "affected"
            }
          ]
        })
      )

      # gone_lib is not stubbed -> hex.pm 404 -> that record errors, the job
      # raises for the Oban retry, but the other record is still created
      assert_raise Ash.Error.Unknown, ~r/gone_lib/, fn -> create_missing() end

      assert get_osv()
      assert Ash.count!(OsvRecord, authorize?: false) == 1
    end

    test "skips non-convertible and unpublished records" do
      import_cve(cve_json(%{affected: []}))

      Ash.create!(
        CveRecord,
        %{
          reservation_json: %{
            "cve_id" => "CVE-2025-99999",
            "cve_year" => "2025",
            "state" => "RESERVED",
            "reserved" => "2025-01-01T00:00:00.000Z"
          }
        },
        action: :reserve,
        authorize?: false
      )

      create_missing()

      assert Ash.count!(OsvRecord, authorize?: false) == 0
    end
  end

  describe "sync trigger" do
    test "does not touch a freshly synced record" do
      import_cve(cve_json())
      create_missing()
      osv = get_osv()

      run_sync_triggers()

      assert get_osv().synced_at == osv.synced_at
    end

    test "re-syncs when the parent CVE record changed and advances modified" do
      import_cve(cve_json())
      create_missing()
      osv = get_osv()

      future = DateTime.utc_now() |> DateTime.add(60, :second) |> DateTime.to_iso8601()
      import_cve(cve_json(%{title: "Updated vulnerability", date_updated: future}))

      run_sync_triggers()

      updated = get_osv()
      assert updated.osv_json["summary"] == "Updated vulnerability"
      assert DateTime.after?(updated.modified_at, osv.modified_at)
      assert updated.osv_json["modified"] == DateTime.to_iso8601(updated.modified_at)
    end

    test "refreshes hex.pm versions after 24 hours without advancing modified on no change" do
      import_cve(cve_json())
      create_missing()
      osv = get_osv()

      backdate_sync(25)
      run_sync_triggers()

      unchanged = get_osv()
      assert unchanged.modified_at == osv.modified_at
      assert DateTime.after?(unchanged.synced_at, osv.synced_at)
    end

    test "advances modified when a new hex.pm release lands inside an affected range" do
      import_cve(cve_json())
      create_missing()
      osv = get_osv()

      Application.put_env(:varsel, :hex_stub_packages, %{
        "test_lib" => ["1.0.0", "1.2.2", "1.2.2-rc.0", "1.2.3", "2.0.0"]
      })

      backdate_sync(25)
      run_sync_triggers()

      updated = get_osv()
      assert [%{"versions" => ["1.0.0", "1.2.2-rc.0", "1.2.2"]}] = updated.osv_json["affected"]
      assert DateTime.after?(updated.modified_at, osv.modified_at)
    end

    test "does not re-sync before 24 hours have passed" do
      import_cve(cve_json())
      create_missing()
      osv = get_osv()

      backdate_sync(23)
      run_sync_triggers()

      assert DateTime.before?(get_osv().synced_at, osv.synced_at)
    end

    test "withdraws the OSV record when the CVE record leaves the published state" do
      cve_record = import_cve(cve_json())
      create_missing()
      osv = get_osv()

      stub_mitre_reject()

      Ash.update!(cve_record, %{rejection_reason: "Duplicate"},
        action: :reject,
        authorize?: false
      )

      run_sync_triggers()

      withdrawn = get_osv()
      assert withdrawn.withdrawn_at
      assert withdrawn.osv_json["withdrawn"] == DateTime.to_iso8601(withdrawn.withdrawn_at)
      assert DateTime.after?(withdrawn.modified_at, osv.modified_at)

      # withdrawal is one-shot: the record is not revisited afterwards
      run_sync_triggers()
      assert get_osv().synced_at == withdrawn.synced_at
    end

    test "leaves the OSV record untouched while the parent is pending_update" do
      import_cve(cve_json())
      create_missing()
      osv = get_osv()

      Varsel.Repo.update_all("cve_records", set: [state: "pending_update"])
      backdate_sync(25)

      run_sync_triggers()

      frozen = get_osv()
      assert frozen.withdrawn_at == nil
      assert frozen.modified_at == osv.modified_at
      # still backdated — the trigger did not pick the record up
      assert DateTime.before?(frozen.synced_at, osv.synced_at)
    end

    test "withdraws when an update makes the record non-convertible and un-withdraws on revert" do
      import_cve(cve_json())
      create_missing()

      future = DateTime.utc_now() |> DateTime.add(60, :second) |> DateTime.to_iso8601()
      import_cve(cve_json(%{affected: [], date_updated: future}))

      run_sync_triggers()

      withdrawn = get_osv()
      assert withdrawn.withdrawn_at
      assert withdrawn.osv_json["withdrawn"]

      # the CVE is updated again to include the affected package
      later = DateTime.utc_now() |> DateTime.add(120, :second) |> DateTime.to_iso8601()
      import_cve(cve_json(%{date_updated: later}))

      run_sync_triggers()

      restored = get_osv()
      assert restored.withdrawn_at == nil
      refute Map.has_key?(restored.osv_json, "withdrawn")
      assert DateTime.after?(restored.modified_at, withdrawn.modified_at)
    end
  end

  describe "notifier" do
    test "creates the OSV record right after a CVE record is imported" do
      import_cve(cve_json())

      Oban.drain_queue(queue: :osv_sync)

      assert get_osv()
    end

    test "withdraws the OSV record right after a published CVE record is rejected" do
      cve_record = import_cve(cve_json())
      Oban.drain_queue(queue: :osv_sync)
      assert get_osv().withdrawn_at == nil

      stub_mitre_reject()

      Ash.update!(cve_record, %{rejection_reason: "Duplicate"},
        action: :reject,
        authorize?: false
      )

      Oban.drain_queue(queue: :osv_sync)

      assert get_osv().withdrawn_at
    end
  end

  defp stub_mitre_reject do
    Req.Test.stub(Varsel.CVE.MitreCveApi, fn conn ->
      if conn.method == "PUT" do
        Req.Test.json(conn, %{"message" => "CVE ID rejected"})
      else
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)
  end
end
