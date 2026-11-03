# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseUpstreamTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias AshOban.Signals.Worker
  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.MitreCveApi
  alias Varsel.CVE.OwnContainer
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/acme/acme_lib"
  @intro_sha String.duplicate("a", 40)
  @fix_sha String.duplicate("b", 40)
  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
  @cve_id "CVE-2026-111497"
  @upstream_org_id "1ad8a6c6-5a6e-4a3b-9b1e-6c2b2c8e4d10"

  @upstream_cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.2",
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "assignerOrgId" => @upstream_org_id,
      "assignerShortName" => "Google",
      "state" => "PUBLISHED",
      "datePublished" => "2026-05-01T10:00:00.000Z",
      "dateUpdated" => "2026-05-01T10:00:00.000Z"
    },
    "containers" => %{
      "cna" => %{
        "providerMetadata" => %{"orgId" => @upstream_org_id, "shortName" => "Google"},
        "title" => "Heap overflow in brotli",
        "descriptions" => [%{"lang" => "en", "value" => "A heap overflow in the brotli decoder."}],
        "affected" => [
          %{"vendor" => "Google", "product" => "brotli", "defaultStatus" => "affected"}
        ],
        "references" => [%{"url" => "https://github.com/google/brotli/security"}]
      }
    }
  }

  setup do
    poc = Fixtures.register_user("upstream_poc_#{System.unique_integer([:positive])}", :poc)

    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.0.0", "v1.4.0"],
      {@repo, @fix_sha} => ["v1.4.0"]
    })

    Application.put_env(:varsel, :hex_stub_packages, ["acme_lib"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    Fixtures.seed_weakness(122, "Heap-based Buffer Overflow")
    Fixtures.seed_attack_pattern(100, "Overflow Buffers")

    case_record =
      Fixtures.open_case(poc, %{
        title: "brotli heap overflow reaches acme_lib",
        description_md: "acme_lib vendors the affected brotli decoder.",
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

    Cases.add_case_weakness!(%{case_id: case_record.id, cwe_id: 122}, actor: poc)
    Cases.add_case_impact!(%{case_id: case_record.id, capec_id: 100}, actor: poc)

    %{poc: poc, case: case_record}
  end

  defp stub_mitre(id_state) do
    Req.Test.stub(MitreCveApi, fn conn ->
      case {conn.method, conn.path_info} do
        {"GET", ["api", "cve-id", @cve_id]} ->
          Req.Test.json(conn, %{
            "cve_id" => @cve_id,
            "cve_year" => "2026",
            "state" => id_state,
            "owning_cna" => if(id_state == "RESERVED", do: "[REDACTED]", else: "Google")
          })

        {"GET", ["api", "cve", @cve_id]} when id_state == "PUBLISHED" ->
          Req.Test.json(conn, @upstream_cve_json)
      end
    end)
  end

  defp link_and_approve(case_record, poc) do
    case_record = Cases.link_case_upstream_cve!(case_record, @cve_id, actor: poc)
    {:ok, case_record} = Cases.refresh_case_derivation(case_record, actor: poc)
    case_record = Cases.request_case_review!(case_record, actor: poc)
    Cases.approve_case!(case_record, actor: poc)
  end

  defp publish(case_record, poc) do
    Cases.publish_case!(case_record, actor: poc)

    assert_enqueued(worker: Worker, args: %{"listener" => "mark_published"})
    Oban.drain_queue(queue: :cve_publishing, with_recursion: true)

    Ash.get!(Cases.Case, case_record.id,
      authorize?: false,
      load: [:preview, :published_container]
    )
  end

  describe "link_upstream_cve" do
    test "links a published upstream CVE", %{poc: poc, case: case_record} do
      stub_mitre("PUBLISHED")

      case_record =
        case_record
        |> Cases.link_case_upstream_cve!(@cve_id, actor: poc)
        |> Ash.load!([:cve_id, :upstream_cve, :upstream_cve_reserved], actor: poc)

      assert case_record.cve_id == @cve_id
      assert case_record.upstream_cve
      refute case_record.upstream_cve_reserved
    end

    test "is POC-only and asks MITRE nothing otherwise", %{poc: poc, case: case_record} do
      Req.Test.stub(MitreCveApi, fn _conn -> flunk("MITRE must not be called") end)

      supporter =
        Fixtures.register_user(
          "upstream_supporter_#{System.unique_integer([:positive])}",
          :supporter
        )

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      assert {:error, %Forbidden{}} =
               Cases.link_case_upstream_cve(case_record, @cve_id, actor: supporter)
    end

    test "and assign_cve_id exclude each other", %{poc: poc, case: case_record} do
      stub_mitre("PUBLISHED")
      Fixtures.reserved_cve_record("CVE-#{Date.utc_today().year}-31337")
      linked = Cases.link_case_upstream_cve!(case_record, @cve_id, actor: poc)

      assert {:error, %Invalid{}} = Cases.assign_case_cve_id(linked, %{}, actor: poc)

      assigned = Cases.assign_case_cve_id!(Fixtures.open_case(poc), %{}, actor: poc)
      assert {:error, %Invalid{}} = Cases.link_case_upstream_cve(assigned, @cve_id, actor: poc)
    end

    test "a failed lookup leaves the case unlinked", %{poc: poc, case: case_record} do
      stub_mitre("REJECTED")

      assert {:error, %Invalid{} = error} =
               Cases.link_case_upstream_cve(case_record, @cve_id, actor: poc)

      assert [%{field: :cve_id, message: "is REJECTED at MITRE"}] = error.errors
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).cve_record_id == nil
    end

    test "a case update that fails leaves no record", %{poc: poc, case: case_record} do
      stub_mitre("PUBLISHED")
      Cases.edit_case!(case_record, %{title: "Moved on"}, actor: poc)

      assert {:error, %Invalid{errors: [%Ash.Error.Changes.StaleRecord{}]}} =
               Cases.link_case_upstream_cve(case_record, @cve_id, actor: poc)

      assert [] == Ash.read!(CveRecord, authorize?: false)
    end
  end

  describe "preview" do
    test "renders MITRE's record with this CNA's ADP container", %{poc: poc, case: case_record} do
      stub_mitre("PUBLISHED")

      %{preview: preview, validation: validation} =
        case_record
        |> Cases.link_case_upstream_cve!(@cve_id, actor: poc)
        |> Cases.refresh_case_derivation!(actor: poc)
        |> Ash.load!([:preview, :validation], actor: poc)

      assert preview.cve_record["cveMetadata"] == @upstream_cve_json["cveMetadata"]
      assert preview.cve_record["containers"]["cna"] == @upstream_cve_json["containers"]["cna"]
      assert [adp] = preview.cve_record["containers"]["adp"]
      assert adp["title"] == "brotli heap overflow reaches acme_lib"
      assert adp["providerMetadata"] == OwnContainer.provider_metadata()
      refute Map.has_key?(adp, "dateAssigned")
      assert preview.blockers == []
      assert validation.valid
    end

    test "blocks while the upstream ID is RESERVED", %{poc: poc, case: case_record} do
      stub_mitre("RESERVED")
      case_record = link_and_approve(case_record, poc)

      %{preview: preview, validation: validation} =
        Ash.load!(case_record, [:preview, :validation], actor: poc)

      assert preview.blockers == [
               "the upstream CVE is still RESERVED at MITRE; publish once its CNA has published it"
             ]

      # A stand-in for MITRE's record keeps the ADP container validatable.
      assert OwnContainer.get(preview.cve_record)["title"] ==
               "brotli heap overflow reaches acme_lib"

      assert validation.valid
      assert preview.osv_record["upstream"] == [@cve_id]

      supporter =
        Fixtures.register_user(
          "upstream_supporter_#{System.unique_integer([:positive])}",
          :supporter
        )

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      %{preview: supporter_preview} = Ash.load!(case_record, :preview, actor: supporter)
      assert supporter_preview.blockers == preview.blockers
      assert supporter_preview.cve_record == preview.cve_record

      assert {:error, error} = Cases.publish_case(case_record, actor: poc)
      assert Exception.message(error) =~ "still RESERVED at MITRE"
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).state == :approved
    end
  end

  describe "publish" do
    test "stores the container as this CNA's enrichment without a MITRE write", %{
      poc: poc,
      case: case_record
    } do
      stub_mitre("PUBLISHED")
      case_record = link_and_approve(case_record, poc)
      Req.Test.stub(MitreCveApi, fn _conn -> flunk("MITRE must not be called") end)

      case_record = publish(case_record, poc)

      assert case_record.state == :published
      cve_record = CVE.get_cve_record!(case_record.cve_record_id, actor: nil)
      assert cve_record.state == :published
      assert cve_record.cve_json["containers"]["cna"] == @upstream_cve_json["containers"]["cna"]

      assert OwnContainer.get(cve_record.cve_json)["title"] ==
               "brotli heap overflow reaches acme_lib"

      # mark_published stamps date_public, so only a fresh render carries datePublic.
      assert case_record.published_container ==
               Map.delete(OwnContainer.get(case_record.preview.cve_record), "datePublic")
    end

    test "derives the OSV document from the enrichment", %{poc: poc, case: case_record} do
      stub_mitre("PUBLISHED")
      case_record = case_record |> link_and_approve(poc) |> publish(poc)

      CVE.create_missing_osv_records!(authorize?: false)

      %{osv_json: osv} = CVE.get_osv_record!("EEF-#{@cve_id}", actor: nil)

      assert osv["aliases"] == ["GHSA-xxxx-yyyy-zzzz"]
      assert osv["upstream"] == [@cve_id]
      assert osv["published"] == "2026-05-01T10:00:00.000Z"
      assert osv["summary"] == "brotli heap overflow reaches acme_lib"

      assert [
               %{"package" => %{"ecosystem" => "Hex", "name" => "acme_lib"}},
               %{"ranges" => [%{"type" => "GIT"}]}
             ] =
               osv["affected"]

      %{preview: preview, published_osv: published_osv} =
        Ash.load!(case_record, [:preview, :published_osv], actor: poc)

      assert published_osv == preview.osv_record
    end

    test "an amendment replaces the enrichment", %{poc: poc, case: case_record} do
      stub_mitre("PUBLISHED")
      case_record = case_record |> link_and_approve(poc) |> publish(poc)

      case_record = Cases.reopen_case!(case_record, actor: poc)
      case_record = Cases.edit_case!(case_record, %{title: "Worse than we thought"}, actor: poc)
      case_record = Cases.request_case_review!(case_record, actor: poc)
      case_record = case_record |> Cases.approve_case!(actor: poc) |> publish(poc)

      assert case_record.state == :published
      assert case_record.published_container["title"] == "Worse than we thought"
    end
  end

  describe "close" do
    test "unlinks an upstream CVE whose enrichment was never published", %{
      poc: poc,
      case: case_record
    } do
      stub_mitre("PUBLISHED")
      case_record = Cases.link_case_upstream_cve!(case_record, @cve_id, actor: poc)

      closed = Cases.close_case!(case_record, %{closed_reason: "Not affected"}, actor: poc)

      assert closed.state == :closed
      assert closed.cve_record_id == nil
      assert [] == Ash.read!(CveRecord, authorize?: false)
    end

    test "refuses to reject an upstream CVE", %{poc: poc, case: case_record} do
      stub_mitre("PUBLISHED")
      case_record = Cases.link_case_upstream_cve!(case_record, @cve_id, actor: poc)

      assert {:error, %Invalid{} = error} =
               Cases.close_case(
                 case_record,
                 %{closed_reason: "Not affected", reject_cve_id: true},
                 actor: poc
               )

      assert [%{field: :reject_cve_id}] = error.errors
    end
  end
end
