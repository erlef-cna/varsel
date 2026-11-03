# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecordUpstreamTest do
  use Varsel.DataCase, async: false

  import Ash.Signals.Test

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.CVE
  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.MitreCveApi
  alias Varsel.CVE.OwnContainer
  alias Varsel.CVE.Signals
  alias Varsel.Fixtures

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
        "problemTypes" => [
          %{
            "descriptions" => [
              %{"cweId" => "CWE-787", "description" => "CWE-787", "lang" => "en", "type" => "CWE"}
            ]
          }
        ],
        "references" => [%{"url" => "https://github.com/google/brotli/security"}]
      }
    }
  }

  @adp_container %{
    "providerMetadata" => %{
      "orgId" => "6b3ad84c-e1a6-4bf7-a703-f496b71e49db",
      "shortName" => "EEF"
    },
    "title" => "brotli heap overflow reaches the brotli hex package",
    "descriptions" => [
      %{"lang" => "en", "value" => "The brotli hex package vendors the affected decoder."}
    ],
    "affected" => [
      %{
        "vendor" => "Erlang Ecosystem Foundation",
        "product" => "brotli",
        "packageURL" => "pkg:hex/brotli",
        "defaultStatus" => "unaffected",
        "versions" => [
          %{
            "version" => "0",
            "lessThan" => "0.3.2",
            "status" => "affected",
            "versionType" => "semver"
          }
        ]
      }
    ],
    "references" => [%{"url" => "https://github.com/google/brotli/security"}],
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
          %{"cweId" => "CWE-122", "description" => "CWE-122", "lang" => "en", "type" => "CWE"}
        ]
      }
    ],
    "impacts" => [
      %{"capecId" => "CAPEC-100", "descriptions" => [%{"lang" => "en", "value" => "CAPEC-100"}]}
    ]
  }

  setup do
    Application.put_env(:varsel, :hex_stub_packages, ["brotli"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)
  end

  defp poc, do: Fixtures.register_user("poc-#{System.unique_integer([:positive])}", :poc)

  defp upstream_record(poc) do
    Req.Test.stub(MitreCveApi, fn conn ->
      case {conn.method, conn.path_info} do
        {"GET", ["api", "cve-id", @cve_id]} ->
          Req.Test.json(conn, %{
            "cve_id" => @cve_id,
            "cve_year" => "2026",
            "state" => "PUBLISHED",
            "owning_cna" => "Google"
          })

        {"GET", ["api", "cve", @cve_id]} ->
          Req.Test.json(conn, @upstream_cve_json)
      end
    end)

    CVE.link_upstream_cve_record!(@cve_id, actor: poc)
  end

  describe "link_upstream" do
    test "a RESERVED ID of another CNA enters :draft with only its ID object" do
      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve-id", @cve_id]} = {conn.method, conn.path_info}

        Req.Test.json(conn, %{
          "cve_id" => @cve_id,
          "cve_year" => "2026",
          "state" => "RESERVED",
          "owning_cna" => "[REDACTED]"
        })
      end)

      record = CVE.link_upstream_cve_record!(@cve_id, actor: poc())

      assert record.state == :draft
      assert record.upstream
      assert record.reservation_json["owning_cna"] == "[REDACTED]"
      assert record.cve_json == nil
    end

    test "a PUBLISHED ID of another CNA enters :draft with MITRE's record" do
      record = upstream_record(poc())

      assert record.state == :draft
      assert record.upstream
      assert record.cve_json == @upstream_cve_json
    end

    test "an ID this CNA reserved is refused" do
      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve-id", @cve_id]} = {conn.method, conn.path_info}

        Req.Test.json(conn, %{
          "cve_id" => @cve_id,
          "cve_year" => "2026",
          "state" => "RESERVED",
          "owning_cna" => "EEF"
        })
      end)

      assert {:error, %Invalid{} = error} = CVE.link_upstream_cve_record(@cve_id, actor: poc())

      assert [
               %{
                 field: :cve_id,
                 message: "is assigned by this CNA; assign it from the pool instead"
               }
             ] = error.errors
    end

    test "a published CVE this CNA assigned is refused" do
      own_cve_json =
        put_in(
          @upstream_cve_json,
          ["cveMetadata", "assignerOrgId"],
          "6b3ad84c-e1a6-4bf7-a703-f496b71e49db"
        )

      Req.Test.stub(MitreCveApi, fn conn ->
        case {conn.method, conn.path_info} do
          {"GET", ["api", "cve-id", @cve_id]} ->
            Req.Test.json(conn, %{
              "cve_id" => @cve_id,
              "cve_year" => "2026",
              "state" => "PUBLISHED",
              "owning_cna" => "EEF"
            })

          {"GET", ["api", "cve", @cve_id]} ->
            Req.Test.json(conn, own_cve_json)
        end
      end)

      assert {:error, %Invalid{} = error} = CVE.link_upstream_cve_record(@cve_id, actor: poc())

      assert [
               %{
                 field: :cve_id,
                 message: "is assigned by this CNA; assign it from the pool instead"
               }
             ] = error.errors
    end

    test "a REJECTED ID is refused" do
      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve-id", @cve_id]} = {conn.method, conn.path_info}

        Req.Test.json(conn, %{
          "cve_id" => @cve_id,
          "cve_year" => "2026",
          "state" => "REJECTED",
          "owning_cna" => "Google"
        })
      end)

      assert {:error, %Invalid{} = error} = CVE.link_upstream_cve_record(@cve_id, actor: poc())
      assert [%{field: :cve_id, message: "is REJECTED at MITRE"}] = error.errors
    end

    test "an ID MITRE does not know is refused" do
      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve-id", @cve_id]} = {conn.method, conn.path_info}

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          404,
          JSON.encode!(%{"error" => "CVEID_NOT_FOUND", "message" => "not found"})
        )
      end)

      assert {:error, %Invalid{} = error} = CVE.link_upstream_cve_record(@cve_id, actor: poc())

      assert [
               %{
                 field: :cve_id,
                 message: "could not be looked up at MITRE: MITRE API error 404: not found"
               }
             ] =
               error.errors
    end

    test "input that is not a CVE ID is refused before any MITRE call" do
      Req.Test.stub(MitreCveApi, fn _conn -> flunk("MITRE must not be called") end)

      assert {:error, %Invalid{} = error} =
               CVE.link_upstream_cve_record("CVE-2026-1/../../x", actor: poc())

      assert [%{field: :cve_id}] = error.errors
    end

    test "an ID that is already linked is refused" do
      poc = poc()
      upstream_record(poc)

      assert {:error, %Invalid{}} = CVE.link_upstream_cve_record(@cve_id, actor: poc)
    end

    test "only a POC may link" do
      Req.Test.stub(MitreCveApi, fn _conn -> flunk("MITRE must not be called") end)

      supporter =
        Fixtures.register_user("supporter-#{System.unique_integer([:positive])}", :supporter)

      roleless = Fixtures.register_user("roleless-#{System.unique_integer([:positive])}")

      assert {:error, %Forbidden{}} = CVE.link_upstream_cve_record(@cve_id, actor: supporter)
      assert {:error, %Forbidden{}} = CVE.link_upstream_cve_record(@cve_id, actor: roleless)
      assert {:error, %Forbidden{}} = CVE.link_upstream_cve_record(@cve_id, actor: nil)
    end
  end

  describe "sync_upstream" do
    test "a still RESERVED ID stays without a record" do
      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve-id", @cve_id]} = {conn.method, conn.path_info}

        Req.Test.json(conn, %{
          "cve_id" => @cve_id,
          "cve_year" => "2026",
          "state" => "RESERVED",
          "owning_cna" => "[REDACTED]"
        })
      end)

      record = CVE.link_upstream_cve_record!(@cve_id, actor: poc())
      synced = CVE.sync_upstream_cve_record!(record, authorize?: false)

      assert synced.state == :draft
      assert synced.cve_json == nil
      assert synced.last_synced_at
    end

    test "an ID the upstream CNA published gets its record" do
      published? = :atomics.new(1, [])

      Req.Test.stub(MitreCveApi, fn conn ->
        case {conn.method, conn.path_info, :atomics.get(published?, 1)} do
          {"GET", ["api", "cve-id", @cve_id], 0} ->
            Req.Test.json(conn, %{
              "cve_id" => @cve_id,
              "cve_year" => "2026",
              "state" => "RESERVED",
              "owning_cna" => "[REDACTED]"
            })

          {"GET", ["api", "cve-id", @cve_id], 1} ->
            Req.Test.json(conn, %{
              "cve_id" => @cve_id,
              "cve_year" => "2026",
              "state" => "PUBLISHED",
              "owning_cna" => "Google"
            })

          {"GET", ["api", "cve", @cve_id], 1} ->
            Req.Test.json(conn, @upstream_cve_json)
        end
      end)

      record = CVE.link_upstream_cve_record!(@cve_id, actor: poc())
      :atomics.put(published?, 1, 1)

      synced =
        refute_emits_signal(Signals, :cve_record_published, fn ->
          CVE.sync_upstream_cve_record!(record, authorize?: false)
        end)

      assert synced.state == :draft
      assert synced.cve_json == @upstream_cve_json
    end

    test "a changed upstream record replaces the local copy and keeps the enrichment" do
      poc = poc()
      record = upstream_record(poc)
      enriched = CVE.publish_cve_record_enrichment!(record, @adp_container, actor: poc)

      changed =
        @upstream_cve_json
        |> put_in(["cveMetadata", "dateUpdated"], "2026-06-01T10:00:00.000Z")
        |> put_in(["containers", "cna", "title"], "Heap overflow in the brotli decoder")

      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve", @cve_id]} = {conn.method, conn.path_info}
        Req.Test.json(conn, changed)
      end)

      id = enriched.id

      synced =
        assert_emits_signal(Signals, :cve_record_published, %{cve_record_id: ^id}, fn ->
          CVE.sync_upstream_cve_record!(enriched, authorize?: false)
        end)

      assert synced.state == :published
      assert synced.cve_json["containers"]["cna"] == changed["containers"]["cna"]
      assert OwnContainer.get(synced.cve_json) == OwnContainer.get(enriched.cve_json)
      # The enrichment was published after MITRE's change, so its date stays.
      assert synced.cve_json["cveMetadata"]["dateUpdated"] ==
               enriched.cve_json["cveMetadata"]["dateUpdated"]
    end

    test "an upstream record MITRE did not change leaves the local copy as it is" do
      poc = poc()

      enriched =
        poc |> upstream_record() |> CVE.publish_cve_record_enrichment!(@adp_container, actor: poc)

      synced =
        refute_emits_signal(Signals, :cve_record_published, fn ->
          CVE.sync_upstream_cve_record!(enriched, authorize?: false)
        end)

      assert synced.cve_json == enriched.cve_json
    end

    test "MITRE's dateUpdated wins when it is the later one" do
      poc = poc()

      enriched =
        poc |> upstream_record() |> CVE.publish_cve_record_enrichment!(@adp_container, actor: poc)

      later =
        put_in(@upstream_cve_json, ["cveMetadata", "dateUpdated"], "2099-01-01T00:00:00.000Z")

      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve", @cve_id]} = {conn.method, conn.path_info}
        Req.Test.json(conn, later)
      end)

      synced = CVE.sync_upstream_cve_record!(enriched, authorize?: false)

      assert synced.cve_json["cveMetadata"]["dateUpdated"] == "2099-01-01T00:00:00.000Z"
      assert OwnContainer.get(synced.cve_json) == OwnContainer.get(enriched.cve_json)
    end

    test "an upstream CVE that MITRE rejected moves to :rejected" do
      poc = poc()

      enriched =
        poc |> upstream_record() |> CVE.publish_cve_record_enrichment!(@adp_container, actor: poc)

      rejected = put_in(@upstream_cve_json, ["cveMetadata", "state"], "REJECTED")

      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve", @cve_id]} = {conn.method, conn.path_info}
        Req.Test.json(conn, rejected)
      end)

      id = enriched.id

      synced =
        assert_emits_signal(Signals, :cve_record_rejected, %{cve_record_id: ^id}, fn ->
          CVE.sync_upstream_cve_record!(enriched, authorize?: false)
        end)

      assert synced.state == :rejected
      assert synced.rejection_reason == "Rejected upstream at MITRE"
    end
  end

  describe "publish_enrichment" do
    test "puts the ADP container into the record, bumps dateUpdated and makes it public" do
      poc = poc()
      record = upstream_record(poc)

      assert {:error, %Invalid{}} = CVE.get_cve_record_by_cve_id(@cve_id, actor: nil)

      id = record.id

      enriched =
        assert_emits_signal(Signals, :cve_record_published, %{cve_record_id: ^id}, fn ->
          CVE.publish_cve_record_enrichment!(record, @adp_container, actor: poc)
        end)

      assert enriched.state == :published
      assert enriched.cve_json["containers"]["cna"] == @upstream_cve_json["containers"]["cna"]
      assert [adp] = enriched.cve_json["containers"]["adp"]
      date_updated = enriched.cve_json["cveMetadata"]["dateUpdated"]

      assert adp ==
               put_in(@adp_container, ["providerMetadata", "dateUpdated"], date_updated)

      assert {:ok, at, 0} = DateTime.from_iso8601(date_updated)
      assert DateTime.after?(at, ~U[2026-05-01 10:00:00Z])
      assert CVE.get_cve_record_by_cve_id!(@cve_id, actor: nil).id == enriched.id
    end

    test "a second publish replaces this CNA's ADP entry" do
      poc = poc()
      record = upstream_record(poc)
      enriched = CVE.publish_cve_record_enrichment!(record, @adp_container, actor: poc)

      updated =
        CVE.publish_cve_record_enrichment!(enriched, %{@adp_container | "title" => "Updated"}, actor: poc)

      assert [%{"title" => "Updated"}] = updated.cve_json["containers"]["adp"]
    end

    test "is refused while the upstream ID is still RESERVED" do
      Req.Test.stub(MitreCveApi, fn conn ->
        {"GET", ["api", "cve-id", @cve_id]} = {conn.method, conn.path_info}

        Req.Test.json(conn, %{
          "cve_id" => @cve_id,
          "cve_year" => "2026",
          "state" => "RESERVED",
          "owning_cna" => "[REDACTED]"
        })
      end)

      poc = poc()
      record = CVE.link_upstream_cve_record!(@cve_id, actor: poc)

      assert {:error, %Invalid{} = error} =
               CVE.publish_cve_record_enrichment(record, @adp_container, actor: poc)

      assert [%{field: :cve_json, message: "the upstream CVE is not published at MITRE yet"}] =
               error.errors
    end

    test "is refused for a CVE this CNA assigned" do
      poc = poc()
      record = Fixtures.published_cve_record("CVE-2026-900001", "Our own CVE")

      refute CVE.can_publish_cve_record_enrichment?(poc, record, @adp_container)

      assert {:error, _error} =
               CVE.publish_cve_record_enrichment(record, @adp_container, actor: poc)

      assert CVE.get_cve_record!(record.id, actor: poc).cve_json == record.cve_json
    end

    test "validates the record against the CVE schema only" do
      poc = poc()
      record = upstream_record(poc)

      assert %{state: :published} =
               CVE.publish_cve_record_enrichment!(record, Map.delete(@adp_container, "impacts"), actor: poc)
    end

    test "refuses a dateAssigned, which the schema allows only in a CNA container" do
      poc = poc()
      record = upstream_record(poc)
      adp_container = Map.put(@adp_container, "dateAssigned", "2026-05-01T10:00:00.000Z")

      assert {:error, %Invalid{} = error} =
               CVE.publish_cve_record_enrichment(record, adp_container, actor: poc)

      assert [%{field: :cve_json, message: "CVE record is not valid:\n[schema]" <> _}] =
               error.errors
    end

    test "is POC-only" do
      record = upstream_record(poc())

      supporter =
        Fixtures.register_user("supporter-#{System.unique_integer([:positive])}", :supporter)

      assert {:error, %Forbidden{}} =
               CVE.publish_cve_record_enrichment(record, @adp_container, actor: supporter)
    end
  end

  describe "content readers" do
    setup do
      poc = poc()

      enriched =
        poc |> upstream_record() |> CVE.publish_cve_record_enrichment!(@adp_container, actor: poc)

      %{enriched: enriched}
    end

    test "the title and purls shown come from this CNA's ADP container", %{enriched: enriched} do
      loaded = Ash.load!(enriched, [:title, :purls], actor: nil)

      assert loaded.title == "brotli heap overflow reaches the brotli hex package"
      assert loaded.purls == ["pkg:hex/brotli"]
    end

    test "CWE IDs come from every container", %{enriched: enriched} do
      assert Ash.load!(enriched, :cwe_ids, actor: nil).cwe_ids == [122, 787]
    end

    test "purl lookup and search read every container", %{enriched: enriched} do
      assert [%{id: id}] = CVE.list_cve_records_by_purl!("pkg:hex/brotli", actor: nil)
      assert id == enriched.id

      assert [%{id: ^id}] = CVE.search_cve_records!("vendors decoder", actor: nil)
      assert [%{id: ^id}] = CVE.search_cve_records!("heap overflow decoder", actor: nil)
    end

    test "the listing includes the enrichment and the statistics leave it out", %{
      enriched: enriched
    } do
      assert [enriched.id] == Enum.map(CVE.list_published_cve_records!(actor: nil), & &1.id)
      assert [] == CVE.count_published_cve_records_by_quarter!(actor: nil)
    end
  end

  describe "unlink_upstream" do
    test "removes an upstream CVE whose enrichment was never published" do
      poc = poc()
      record = upstream_record(poc)

      :ok = CVE.unlink_upstream_cve_record!(record, actor: poc)

      assert [] == Ash.read!(CveRecord, authorize?: false)
    end

    test "keeps a published enrichment" do
      poc = poc()

      enriched =
        poc |> upstream_record() |> CVE.publish_cve_record_enrichment!(@adp_container, actor: poc)

      assert {:error, %Forbidden{}} = CVE.unlink_upstream_cve_record(enriched, actor: poc)
    end
  end

  describe "MITRE and pool actions" do
    defp refuse_mitre do
      Req.Test.stub(MitreCveApi, fn _conn -> flunk("MITRE must not be called") end)
    end

    test "refuse an upstream draft" do
      poc = poc()
      record = upstream_record(poc)
      refuse_mitre()

      refute CVE.can_request_publish_cve_record?(poc, record, %{cve_json: @upstream_cve_json})

      assert {:error, %Forbidden{}} = CVE.release_cve_record(record, actor: poc)

      assert {:error, %Forbidden{}} =
               CVE.reject_cve_record(record, %{rejection_reason: "test"}, actor: poc)
    end

    test "refuse a published enrichment" do
      poc = poc()

      enriched =
        poc |> upstream_record() |> CVE.publish_cve_record_enrichment!(@adp_container, actor: poc)

      refuse_mitre()

      refute CVE.can_update_cve_record?(poc, enriched, %{cve_json: @upstream_cve_json})

      assert {:error, %Forbidden{}} =
               CVE.reject_cve_record(enriched, %{rejection_reason: "test"}, actor: poc)
    end

    test "refuse an upstream row inside an Oban worker" do
      poc = poc()

      enriched =
        poc |> upstream_record() |> CVE.publish_cve_record_enrichment!(@adp_container, actor: poc)

      refuse_mitre()

      assert {:error, %Forbidden{}} =
               Ash.update(enriched, %{},
                 action: :push_update,
                 context: %{private: %{ash_oban?: true}}
               )
    end
  end
end
