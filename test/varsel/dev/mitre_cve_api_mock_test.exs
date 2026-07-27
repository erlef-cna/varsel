# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Dev.MitreCveApiMockTest do
  use Varsel.DataCase, async: false

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.MitreCveApi
  alias Varsel.Dev.MitreCveApiMock

  @year Date.utc_today().year
  @cve_id "CVE-#{@year}-912345"

  @cna_container %{
    "providerMetadata" => %{"orgId" => "b33eab0a-aa47-4189-b7ec-b71bbfeee3e3"},
    "title" => "Test vulnerability",
    "descriptions" => [
      %{"lang" => "en", "value" => "A test vulnerability in test_lib allowing denial of service."}
    ],
    "affected" => [
      %{
        "vendor" => "Erlang Ecosystem Foundation",
        "product" => "test_lib",
        "packageURL" => "pkg:hex/test_lib",
        "defaultStatus" => "unaffected",
        "versions" => [
          %{
            "version" => "0",
            "lessThan" => "1.2.3",
            "status" => "affected",
            "versionType" => "semver"
          }
        ]
      }
    ],
    "references" => [%{"url" => "https://example.com/advisory"}],
    "metrics" => [
      %{
        "cvssV4_0" => %{
          "version" => "4.0",
          "vectorString" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
          "baseScore" => 8.7,
          "baseSeverity" => "HIGH"
        }
      }
    ],
    "problemTypes" => [
      %{
        "descriptions" => [
          %{"cweId" => "CWE-400", "description" => "CWE-400", "lang" => "en", "type" => "CWE"}
        ]
      }
    ],
    "impacts" => [
      %{"capecId" => "CAPEC-125", "descriptions" => [%{"lang" => "en", "value" => "CAPEC-125"}]}
    ]
  }

  @updated_cna_container %{@cna_container | "title" => "Updated vulnerability"}

  @cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.1",
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "assignerOrgId" => "b33eab0a-aa47-4189-b7ec-b71bbfeee3e3",
      "assignerShortName" => "EEF",
      "state" => "PUBLISHED"
    },
    "containers" => %{"cna" => @cna_container}
  }

  setup do
    Application.put_env(:varsel, :hex_stub_packages, ["test_lib"])

    original = Application.get_env(:varsel, :mitre_cve_api)

    Application.put_env(:varsel, :mitre_cve_api,
      base_url: "http://mitre.invalid",
      org: "EEF",
      user: "mock@localhost",
      api_key: "mock",
      plug: MitreCveApiMock
    )

    on_exit(fn ->
      Application.put_env(:varsel, :mitre_cve_api, original)
      Application.delete_env(:varsel, :hex_stub_packages)
      MitreCveApiMock.reset()
    end)

    :ok
  end

  defp reservation_json(cve_id) do
    %{
      "cve_id" => cve_id,
      "cve_year" => to_string(@year),
      "owning_cna" => "EEF",
      "requested_by" => %{"cna" => "EEF", "user" => "test@example.com"},
      "reserved" => "#{@year}-01-01T00:00:00.000Z",
      "state" => "RESERVED",
      "time" => %{
        "created" => "#{@year}-01-01T00:00:00.000Z",
        "modified" => "#{@year}-01-01T00:00:00.000Z"
      }
    }
  end

  defp reserved_record(cve_id \\ @cve_id) do
    Ash.create!(CveRecord, %{reservation_json: reservation_json(cve_id)},
      action: :reserve,
      authorize?: false
    )
  end

  defp publishing_record do
    record = reserved_record()
    draft = Ash.update!(record, %{}, action: :assign, authorize?: false)
    Ash.update!(draft, %{cve_json: @cve_json}, action: :request_publish, authorize?: false)
  end

  describe "reserve" do
    test "returns the requested amount of fresh, well-formed reservations" do
      existing = reserved_record()
      existing_id = Ash.load!(existing, [:cve_id], authorize?: false).cve_id

      assert {:ok, reservations} = MitreCveApi.reserve(@year, 5)
      assert length(reservations) == 5

      ids = Enum.map(reservations, & &1["cve_id"])
      assert length(Enum.uniq(ids)) == 5
      refute existing_id in ids

      for reservation <- reservations do
        assert reservation["cve_id"] =~ ~r/^CVE-#{@year}-9\d{5}$/
        assert reservation["cve_year"] == to_string(@year)
        assert reservation["state"] == "RESERVED"
        assert reservation["owning_cna"] == "EEF"
        assert %{"cna" => "EEF"} = reservation["requested_by"]
        assert {:ok, _reserved, _offset} = DateTime.from_iso8601(reservation["reserved"])
      end
    end

    test "reservations round-trip through the :reserve action" do
      assert {:ok, reservations} = MitreCveApi.reserve(@year, 3)

      inputs = Enum.map(reservations, &%{reservation_json: &1})
      Varsel.CVE.reserve_cve_record!(inputs, authorize?: false)

      assert Ash.count!(CveRecord, authorize?: false) == 3
    end
  end

  describe "publish and get" do
    test "get returns the complete published record" do
      assert {:ok, _body} = MitreCveApi.publish(@cve_id, @cna_container)
      assert {:ok, record} = MitreCveApi.get(@cve_id)

      assert record["dataType"] == "CVE_RECORD"
      assert record["dataVersion"] == "5.2"
      assert record["containers"] == %{"cna" => @cna_container}

      metadata = record["cveMetadata"]
      assert metadata["cveId"] == @cve_id
      assert metadata["state"] == "PUBLISHED"
      assert metadata["assignerOrgId"] == Application.fetch_env!(:varsel, :cna_org_id)
      assert metadata["assignerShortName"] == "EEF"
      assert {:ok, _published, _offset} = DateTime.from_iso8601(metadata["datePublished"])
      assert {:ok, _updated, _offset} = DateTime.from_iso8601(metadata["dateUpdated"])
    end

    test "update_cna preserves datePublished and bumps dateUpdated" do
      assert {:ok, _body} = MitreCveApi.publish(@cve_id, @cna_container)
      assert {:ok, published} = MitreCveApi.get(@cve_id)

      assert {:ok, _body} = MitreCveApi.update_cna(@cve_id, @updated_cna_container)
      assert {:ok, updated} = MitreCveApi.get(@cve_id)

      assert updated["containers"] == %{"cna" => @updated_cna_container}

      assert updated["cveMetadata"]["datePublished"] ==
               published["cveMetadata"]["datePublished"]

      {:ok, updated_at, _offset} = DateTime.from_iso8601(updated["cveMetadata"]["dateUpdated"])

      {:ok, published_at, _offset} =
        DateTime.from_iso8601(published["cveMetadata"]["dateUpdated"])

      assert DateTime.compare(updated_at, published_at) != :lt
    end

    test "get for an unpublished pool record is a 404" do
      reserved_record()

      assert {:error, message} = MitreCveApi.get(@cve_id)
      assert message =~ "404"
    end
  end

  describe "publish worker flow" do
    test "lands the record in :published with dates set, surviving a mock reset" do
      record = publishing_record()

      published = Ash.update!(record, %{}, action: :publish, authorize?: false)

      assert published.state == :published

      loaded = Ash.load!(published, [:date_published, :date_updated], authorize?: false)
      assert %DateTime{} = loaded.date_published
      assert %DateTime{} = loaded.date_updated

      # Simulates a BEAM restart: get falls back to the cve_json stored on the
      # record, so the nightly sync_from_mitre stays a no-op.
      MitreCveApiMock.reset()

      assert {:ok, fetched} = MitreCveApi.get(@cve_id)
      assert fetched == published.cve_json

      synced = Ash.update!(published, %{}, action: :sync_from_mitre, authorize?: false)
      assert synced.cve_json == published.cve_json
    end
  end

  describe "listings and reject" do
    test "published and rejected listings are empty" do
      assert Enum.to_list(MitreCveApi.stream_ids()) == []
      assert Enum.to_list(MitreCveApi.stream_rejected_ids()) == []
    end

    test "the reserved listing holds the seed reservations" do
      reservations = Enum.to_list(MitreCveApi.stream_reserved_ids())

      assert Enum.map(reservations, & &1["cve_id"]) ==
               Enum.map(1..5, &"CVE-#{@year}-90000#{&1}")

      assert Enum.all?(reservations, &(&1["state"] == "RESERVED"))
    end

    test "seed reservations that progressed past :reserved are no longer listed" do
      record = reserved_record("CVE-#{@year}-900002")
      Ash.update!(record, %{}, action: :assign, authorize?: false)

      ids = Enum.map(MitreCveApi.stream_reserved_ids(), & &1["cve_id"])

      refute "CVE-#{@year}-900002" in ids
      assert length(ids) == 4
    end

    test "sync_reserved_from_mitre seeds an empty pool" do
      Varsel.CVE.sync_reserved_cves_from_mitre!(authorize?: false)

      records = Ash.read!(CveRecord, authorize?: false, load: [:cve_id])

      assert length(records) == 5
      assert Enum.all?(records, &(&1.state == :reserved))
      assert Enum.all?(records, &(&1.cve_id =~ ~r/^CVE-#{@year}-90000[1-5]$/))
    end

    test "reject succeeds" do
      assert {:ok, _body} = MitreCveApi.reject(@cve_id)
    end
  end
end
