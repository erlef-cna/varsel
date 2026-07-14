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
        "references" => [%{"url" => "https://example.com/advisory"}]
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

  test "cvelint findings are reported" do
    # E004: descriptions must not have leading or trailing whitespace
    invalid =
      put_in(
        @valid_cve_json,
        ["containers", "cna", "descriptions"],
        [%{"lang" => "en", "value" => "  A test vulnerability with stray whitespace.  "}]
      )

    assert %{valid: false, errors: errors} = CVE.validate_cve_record!(invalid)
    assert Enum.any?(errors, &(&1.source == :cvelint and &1.message =~ "E004"))
  end

  test "missing hex packages are reported" do
    invalid =
      put_in(
        @valid_cve_json,
        ["containers", "cna", "affected", Access.at(0), "packageURL"],
        "pkg:hex/ghost_package"
      )

    assert %{valid: false, errors: errors} = CVE.validate_cve_record!(invalid)
    assert [%{source: :hex, message: message}] = errors
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
