# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CasePublishHandoffTest do
  use Varsel.DataCase, async: false

  alias Varsel.CVE.MitreCveApi
  alias Varsel.Fixtures

  @cve_id "CVE-2026-90001"
  @cna_container %{
    "providerMetadata" => %{"orgId" => "11111111-1111-1111-1111-111111111111"},
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
  @cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.1",
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "assignerOrgId" => "11111111-1111-1111-1111-111111111111",
      "assignerShortName" => "EEF",
      "state" => "PUBLISHED"
    },
    "containers" => %{"cna" => @cna_container}
  }
  @published_cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.1",
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "assignerOrgId" => "11111111-1111-1111-1111-111111111111",
      "assignerShortName" => "EEF",
      "state" => "PUBLISHED",
      "datePublished" => "2026-04-27T12:00:00.000Z",
      "dateUpdated" => "2026-04-27T12:00:00.000Z"
    },
    "containers" => %{"cna" => @cna_container}
  }

  setup do
    Application.put_env(:varsel, :hex_stub_packages, ["test_lib"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)
  end

  test "the record's publish enqueues mark_published for its publishing case" do
    poc = Fixtures.register_user("handoff_poc_#{System.unique_integer([:positive])}", :poc)
    record = Fixtures.reserved_cve_record(@cve_id)
    record = Ash.update!(record, %{}, action: :assign, authorize?: false)
    case_record = Fixtures.open_case(poc, %{title: "Handoff"})

    case_record =
      Ash.Seed.update!(case_record, %{state: :publishing, cve_record_id: record.id})

    record = Ash.Seed.update!(record, %{state: :publishing, cve_json: @cve_json})

    Req.Test.stub(MitreCveApi, fn conn ->
      Req.Test.json(conn, @published_cve_json)
    end)

    {:ok, published} =
      Ash.update(record, %{},
        action: :publish,
        authorize?: false,
        context: %{private: %{ash_oban?: true}}
      )

    assert published.state == :published

    jobs = all_enqueued(worker: Varsel.Cases.Case.MarkPublishedWorker)

    assert Enum.any?(jobs, &(&1.args["primary_key"]["id"] == case_record.id)),
           "no mark_published job enqueued for the case; enqueued: #{inspect(Enum.map(jobs, & &1.args))}"
  end
end
