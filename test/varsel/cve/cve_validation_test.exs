# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidationTest do
  use Varsel.DataCase, async: false

  alias Varsel.CVE
  alias Varsel.CVE.CveValidation

  @org_id "b33eab0a-aa47-4189-b7ec-b71bbfeee3e3"

  @valid_cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.1",
    "cveMetadata" => %{
      "cveId" => "CVE-2025-12345",
      "assignerOrgId" => @org_id,
      "assignerShortName" => "EEF",
      "state" => "PUBLISHED"
    },
    "containers" => %{
      "cna" => %{
        "providerMetadata" => %{"orgId" => @org_id},
        "title" => "Test vulnerability",
        "descriptions" => [
          %{
            "lang" => "en",
            "value" => "A test vulnerability in test_lib allowing denial of service."
          }
        ],
        "affected" => [
          %{
            "vendor" => "Erlang Ecosystem Foundation",
            "product" => "test_lib",
            "packageURL" => "pkg:hex/test_lib@1.0.0",
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
          %{
            "capecId" => "CAPEC-125",
            "descriptions" => [%{"lang" => "en", "value" => "CAPEC-125"}]
          }
        ]
      }
    }
  }

  setup do
    Application.put_env(:varsel, :hex_stub_packages, ["test_lib"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)
  end

  test "a valid record passes all validators" do
    assert %{valid: true, errors: []} = CVE.validate_cve_record!(@valid_cve_json)
  end

  test "schema violations are reported" do
    invalid = put_in(@valid_cve_json, ["cveMetadata", "state"], "BOGUS")

    assert %{valid: false, errors: errors} = CVE.validate_cve_record!(invalid)
    assert Enum.any?(errors, &(&1.source == :schema))
  end

  test "the EEF policy validator flags missing title, CVSS v4, id, CWE and CAPEC" do
    stripped =
      @valid_cve_json
      |> update_in(["containers", "cna"], &Map.drop(&1, ~w(title metrics problemTypes impacts)))
      |> put_in(["cveMetadata", "cveId"], "CVE-0000-0000")

    assert %{valid: false, errors: errors} = CVE.validate_cve_record_eef!(stripped)
    by_code = Map.new(errors, &{&1.code, &1.message})
    assert by_code["EEF001"] == "title is missing"
    assert by_code["EEF002"] == "CVSS v4 vector is missing"
    assert by_code["EEF003"] == "no CVE ID assigned"
    assert by_code["EEF004"] == "no CWE weakness recorded"
    assert by_code["EEF005"] == "no CAPEC attack pattern recorded"
  end

  test "the EEF policy validator accepts a real CVE ID" do
    assert %{valid: true, errors: []} = CVE.validate_cve_record_eef!(@valid_cve_json)
  end

  test "cvelint findings are reported" do
    # E004: descriptions must not have leading or trailing whitespace
    invalid =
      put_in(
        @valid_cve_json,
        ["containers", "cna", "descriptions"],
        [%{"lang" => "en", "value" => "  A test vulnerability with stray whitespace.  "}]
      )

    assert %{valid: false, errors: errors} = CVE.validate_cve_record!(invalid)
    assert Enum.any?(errors, &(&1.source == :cvelint and &1.code == "E004"))
  end

  test "a cveId that is not a CVE ID cannot steer the cvelint temp file" do
    # The id names the temp file cvelint reads, and any authenticated user can
    # reach this action, so a traversing id must not escape the temp directory.
    traversing =
      put_in(@valid_cve_json, ["cveMetadata", "cveId"], "../../../../tmp/varsel-cvelint-escape")

    assert %{valid: _} = CVE.validate_cve_record_cvelint!(traversing)
    refute File.exists?("/tmp/varsel-cvelint-escape.json")
  end

  test "missing hex packages are reported" do
    invalid =
      put_in(
        @valid_cve_json,
        ["containers", "cna", "affected", Access.at(0), "packageURL"],
        "pkg:hex/ghost_package"
      )

    assert %{valid: false, errors: errors} = CVE.validate_cve_record!(invalid)
    assert [%{source: :hex, code: "HEX001", message: message}] = errors
    assert message =~ "ghost_package"
  end

  test "namespaced (private org) hex purls are skipped" do
    record =
      put_in(
        @valid_cve_json,
        ["containers", "cna", "affected", Access.at(0), "packageURL"],
        "pkg:hex/acme/private_pkg"
      )

    assert %{valid: true} = CVE.validate_cve_record!(record)
  end

  test "non-hex purls are skipped" do
    record =
      put_in(
        @valid_cve_json,
        ["containers", "cna", "affected", Access.at(0), "packageURL"],
        "pkg:cargo/some_crate"
      )

    assert %{valid: true} = CVE.validate_cve_record!(record)
  end

  test "individual validator actions are exposed" do
    invalid = put_in(@valid_cve_json, ["cveMetadata", "state"], "BOGUS")

    assert %{valid: false} =
             CveValidation
             |> Ash.ActionInput.for_action(:validate_schema, %{cve_json: invalid})
             |> Ash.run_action!()

    assert %{valid: true} =
             CveValidation
             |> Ash.ActionInput.for_action(:validate_hex_packages, %{cve_json: invalid})
             |> Ash.run_action!()
  end
end
