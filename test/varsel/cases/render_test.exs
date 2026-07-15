# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.RenderTest do
  @moduledoc """
  Golden test: a case modelled after the published CVE-2025-4754 record
  (ash_authentication_phoenix) must render the same structured CNA data —
  affected entries, cpeApplicability, problemTypes, impacts, credits, metrics
  and reference order. Prose (descriptions) is authored per case, so only its
  markdown round-trip is asserted, not byte parity with the old record.
  """

  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Cases.Publication
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/team-alembic/ash_authentication_phoenix"
  @fix_sha "a3253fb4fc7145aeb403537af1c24d3a8d51ffb1"
  @cpe "cpe:2.3:a:team-alembic:ash_authentication_phoenix:*:*:*:*:*:*:*:*"
  @vector "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
  @advisory "https://github.com/team-alembic/ash_authentication_phoenix/security/advisories/GHSA-f7gq-h8jv-h3cq"

  setup do
    poc = Fixtures.register_user("render_poc", :poc)

    Fixtures.seed_weakness(613, "Insufficient Session Expiration")
    Fixtures.seed_attack_pattern(593, "Session Hijacking")

    StubGitBackend.stub_tags(%{{@repo, @fix_sha} => ["v2.10.0"]})

    Application.put_env(:varsel, :hex_stub_packages, ["ash_authentication_phoenix"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    case_record =
      Fixtures.open_case(poc, %{
        title: "Missing Session Revocation on Logout in ash_authentication_phoenix",
        description_md:
          "Insufficient Session Expiration vulnerability in ash-project " <>
            "ash_authentication_phoenix allows Session Hijacking.\n\n" <>
            "This issue affects ash_authentication_phoenix until 2.10.0.",
        cvss_v4: @vector
      })

    package =
      Fixtures.add_affected_package(poc, case_record, %{
        vendor: "ash-project",
        product: "ash_authentication_phoenix",
        repo_url: @repo,
        cpe: @cpe,
        program_files: ["lib/ash_authentication_phoenix/controller.ex"]
      })

    Cases.add_package_channel!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        channel_type: :hex,
        package_name: "ash_authentication_phoenix",
        position: 0
      },
      actor: poc
    )

    Cases.add_package_channel!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        channel_type: :git,
        package_name: "team-alembic/ash_authentication_phoenix",
        position: 1
      },
      actor: poc
    )

    # Affected since the first release; fixed in 2.10.0.
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
        url: @advisory,
        tags: ["vendor-advisory", "related"],
        position: 0
      },
      actor: poc
    )

    Cases.add_case_reference!(
      %{
        case_id: case_record.id,
        url: "https://github.com/team-alembic/ash_authentication_phoenix/pull/634",
        tags: ["patch"],
        position: 1
      },
      actor: poc
    )

    Cases.add_case_weakness!(%{case_id: case_record.id, cwe_id: 613}, actor: poc)
    Cases.add_case_impact!(%{case_id: case_record.id, capec_id: 593}, actor: poc)

    for {name, organization, type, position} <- [
          {"James Harton", nil, :remediation_reviewer, 0},
          {"Zach Daniel", nil, :remediation_developer, 1},
          {"Mike Buhot", nil, :analyst, 2},
          {"Jonatan Männchen", "EEF", :analyst, 3},
          {"Josh Price", nil, :analyst, 4}
        ] do
      Cases.add_case_credit!(
        %{
          case_id: case_record.id,
          name: name,
          organization: organization,
          credit_type: type,
          position: position
        },
        actor: poc
      )
    end

    # The published record's CVE ID, reserved then assigned to the case.
    reserved = Fixtures.reserved_cve_record("CVE-2025-4754")

    case_record =
      Cases.assign_case_cve_id!(case_record, %{cve_record_id: reserved.id}, actor: poc)

    %{poc: poc, case: case_record}
  end

  defp render!(case_record) do
    {:ok, %{result: result, cve_json: cve_json}} = Publication.render(case_record, refresh: true)
    {result, cve_json}
  end

  test "renders the affected entries exactly as published", %{case: case_record} do
    {result, _cve_json} = render!(case_record)

    assert result.cna["affected"] == [
             %{
               "collectionURL" => "https://repo.hex.pm",
               "cpes" => [@cpe],
               "defaultStatus" => "unaffected",
               "packageName" => "ash_authentication_phoenix",
               "packageURL" => "pkg:hex/ash_authentication_phoenix",
               "product" => "ash_authentication_phoenix",
               "programFiles" => ["lib/ash_authentication_phoenix/controller.ex"],
               "repo" => @repo,
               "vendor" => "ash-project",
               "versions" => [
                 %{
                   "lessThan" => "2.10.0",
                   "status" => "affected",
                   "version" => "0",
                   "versionType" => "semver"
                 }
               ]
             },
             %{
               "collectionURL" => "https://github.com",
               "cpes" => [@cpe],
               "defaultStatus" => "unaffected",
               "packageName" => "team-alembic/ash_authentication_phoenix",
               "packageURL" => "pkg:github/team-alembic/ash_authentication_phoenix",
               "product" => "ash_authentication_phoenix",
               "programFiles" => ["lib/ash_authentication_phoenix/controller.ex"],
               "repo" => @repo,
               "vendor" => "ash-project",
               "versions" => [
                 %{
                   "lessThan" => @fix_sha,
                   "status" => "affected",
                   "version" => "0",
                   "versionType" => "git"
                 }
               ]
             }
           ]
  end

  test "renders cpeApplicability without a lower bound for a \"0\" intro", %{case: case_record} do
    {result, _cve_json} = render!(case_record)

    assert result.cna["cpeApplicability"] == [
             %{
               "operator" => "AND",
               "nodes" => [
                 %{
                   "operator" => "OR",
                   "negate" => false,
                   "cpeMatch" => [
                     %{
                       "criteria" => @cpe,
                       "versionEndExcluding" => "2.10.0",
                       "vulnerable" => true
                     }
                   ]
                 }
               ]
             }
           ]
  end

  test "renders classifications, credits and metrics as published", %{case: case_record} do
    {result, _cve_json} = render!(case_record)

    assert result.cna["problemTypes"] == [
             %{
               "descriptions" => [
                 %{
                   "cweId" => "CWE-613",
                   "description" => "CWE-613 Insufficient Session Expiration",
                   "lang" => "en",
                   "type" => "CWE"
                 }
               ]
             }
           ]

    assert result.cna["impacts"] == [
             %{
               "capecId" => "CAPEC-593",
               "descriptions" => [%{"lang" => "en", "value" => "CAPEC-593 Session Hijacking"}]
             }
           ]

    assert result.cna["credits"] == [
             %{"lang" => "en", "type" => "remediation reviewer", "value" => "James Harton"},
             %{"lang" => "en", "type" => "remediation developer", "value" => "Zach Daniel"},
             %{"lang" => "en", "type" => "analyst", "value" => "Mike Buhot"},
             %{"lang" => "en", "type" => "analyst", "value" => "Jonatan Männchen / EEF"},
             %{"lang" => "en", "type" => "analyst", "value" => "Josh Price"}
           ]

    assert [
             %{
               "format" => "CVSS",
               "scenarios" => [%{"lang" => "en", "value" => "GENERAL"}],
               "cvssV4_0" => cvss
             }
           ] =
             result.cna["metrics"]

    assert cvss["vectorString"] == @vector
    assert cvss["baseScore"] == 2.3
    assert cvss["baseSeverity"] == "LOW"
    assert cvss["attackVector"] == "NETWORK"
    assert cvss["attackRequirements"] == "PRESENT"
    assert cvss["userInteraction"] == "PASSIVE"
    assert cvss["Automatable"] == "NOT_DEFINED"
    assert cvss["providerUrgency"] == "NOT_DEFINED"
    refute Map.has_key?(cvss, "exploitMaturity")
  end

  test "orders references: advisory, self-links, stored patches, fix commits", %{
    case: case_record
  } do
    {result, _cve_json} = render!(case_record)

    assert Enum.map(result.cna["references"], & &1["url"]) == [
             @advisory,
             "https://cna.erlef.org/cves/CVE-2025-4754.html",
             "https://osv.dev/vulnerability/EEF-CVE-2025-4754",
             "https://github.com/team-alembic/ash_authentication_phoenix/pull/634",
             "#{@repo}/commit/#{@fix_sha}"
           ]

    assert List.first(result.cna["references"])["tags"] == ["vendor-advisory", "related"]
  end

  test "derives prose from markdown with both representations", %{case: case_record} do
    {result, _cve_json} = render!(case_record)

    assert [%{"lang" => "en", "value" => plaintext, "supportingMedia" => [media]}] =
             result.cna["descriptions"]

    assert plaintext =~ "Insufficient Session Expiration vulnerability"
    assert plaintext =~ "\n\nThis issue affects"
    assert media["type"] == "text/html"
    assert media["base64"] == false
    assert media["value"] =~ "<p>"
  end

  test "assembles the full record and it passes schema validation", %{case: case_record} do
    {result, cve_json} = render!(case_record)

    assert result.blockers == []
    assert cve_json["cveMetadata"]["cveId"] == "CVE-2025-4754"
    assert cve_json["cveMetadata"]["assignerShortName"] == "EEF"
    assert cve_json["dataType"] == "CVE_RECORD"

    assert %{valid: true, errors: []} = Publication.validate(cve_json)
  end

  test "escape hatches: versions_override, entry_override, cna_override", %{
    poc: poc,
    case: case_record
  } do
    case_record = Ash.load!(case_record, [affected_packages: [:channels]], authorize?: false)
    [package] = case_record.affected_packages
    hex_channel = Enum.find(package.channels, &(&1.channel_type == :hex))

    Cases.edit_package_channel!(
      hex_channel,
      %{
        versions_override: [
          %{
            "version" => "1.0.0",
            "lessThan" => "9.9.9",
            "status" => "affected",
            "versionType" => "semver"
          }
        ],
        entry_override: %{"platforms" => ["BEAM"]}
      },
      actor: poc
    )

    Cases.edit_case!(case_record, %{cna_override: %{"tags" => ["exclusively-hosted-service"]}}, actor: poc)

    case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)
    {result, _cve_json} = render!(case_record)

    hex_entry = Enum.find(result.cna["affected"], &(&1["collectionURL"] == "https://repo.hex.pm"))

    assert hex_entry["versions"] == [
             %{
               "version" => "1.0.0",
               "lessThan" => "9.9.9",
               "status" => "affected",
               "versionType" => "semver"
             }
           ]

    assert hex_entry["platforms"] == ["BEAM"]
    assert result.cna["tags"] == ["exclusively-hosted-service"]

    assert "ash_authentication_phoenix/hex: versions_override" in result.overrides_applied
    assert "ash_authentication_phoenix/hex: entry_override" in result.overrides_applied
    assert "cna_override" in result.overrides_applied
  end

  test "publish blockers surface missing facts", %{poc: poc} do
    empty_case = Fixtures.open_case(poc, %{title: nil})

    {:ok, %{result: result}} = Publication.render(empty_case)

    assert "title is missing" in result.blockers
    assert "description is missing" in result.blockers
    assert "CVSS v4 vector is missing" in result.blockers
    assert "no affected packages recorded" in result.blockers
    assert "no CVE ID assigned" in result.blockers
  end

  test "a pending fix blocks publish unless allowed", %{poc: poc, case: case_record} do
    StubGitBackend.stub_tags(%{{@repo, @fix_sha} => []})

    {result, _cve_json} = render!(case_record)
    assert Enum.any?(result.blockers, &(&1 =~ "no containing release"))

    case_record = Ash.load!(case_record, [:affected_packages], authorize?: false)
    [package] = case_record.affected_packages
    Cases.edit_affected_package!(package, %{allow_unreleased_fix: true}, actor: poc)

    case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)
    {result, _cve_json} = render!(case_record)
    refute Enum.any?(result.blockers, &(&1 =~ "no containing release"))
  end

  describe "forge handling on git channels" do
    setup %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Forge case"})
      %{forge_case: case_record}
    end

    defp git_entry(poc, case_record, repo_url, package_name) do
      package =
        Fixtures.add_affected_package(poc, case_record, %{
          vendor: "acme",
          product: "acme_lib",
          repo_url: repo_url
        })

      Cases.add_package_channel!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          channel_type: :git,
          package_name: package_name
        },
        actor: poc
      )

      case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)
      {:ok, %{result: result}} = Publication.render(case_record)

      Enum.find(
        result.cna["affected"],
        &(&1["collectionURL"] =~ ~r{^https://} or is_nil(&1["collectionURL"]))
      )
    end

    test "a pasted clone URL as package name is normalized, never percent-encoded", %{
      poc: poc,
      forge_case: case_record
    } do
      entry =
        git_entry(
          poc,
          case_record,
          "https://github.com/ZenHive/mpp",
          "https://github.com/ZenHive/mpp"
        )

      assert entry["packageName"] == "ZenHive/mpp"
      assert entry["packageURL"] == "pkg:github/ZenHive/mpp"
      assert entry["collectionURL"] == "https://github.com"
    end

    test "package name defaults from the repository URL", %{poc: poc, forge_case: case_record} do
      entry = git_entry(poc, case_record, "https://github.com/acme/acme_lib.git", nil)

      assert entry["packageName"] == "acme/acme_lib"
      assert entry["packageURL"] == "pkg:github/acme/acme_lib"
    end

    test "gitlab repos get gitlab purls and collectionURL, subgroups included", %{
      poc: poc,
      forge_case: case_record
    } do
      entry = git_entry(poc, case_record, "https://gitlab.com/group/subgroup/acme_lib", nil)

      assert entry["collectionURL"] == "https://gitlab.com"
      assert entry["packageName"] == "group/subgroup/acme_lib"
      assert entry["packageURL"] == "pkg:gitlab/group/subgroup/acme_lib"
    end

    test "forges without a purl type keep the path but emit no packageURL", %{
      poc: poc,
      forge_case: case_record
    } do
      entry = git_entry(poc, case_record, "https://git.sr.ht/~acme/acme_lib", nil)

      assert entry["collectionURL"] == "https://git.sr.ht"
      assert entry["packageName"] == "~acme/acme_lib"
      refute Map.has_key?(entry, "packageURL")
      assert entry["repo"] == "https://git.sr.ht/~acme/acme_lib"
    end

    test "a git channel requires a repository URL on the package", %{
      poc: poc,
      forge_case: case_record
    } do
      package =
        Fixtures.add_affected_package(poc, case_record, %{repo_url: nil, product: "hosted-only"})

      assert {:error, error} =
               Cases.add_package_channel(
                 %{case_id: case_record.id, affected_package_id: package.id, channel_type: :git},
                 actor: poc
               )

      assert Exception.message(error) =~ "needs a repository URL"
    end
  end
end
