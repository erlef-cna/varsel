# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecordPolicyTest do
  use Varsel.DataCase, async: false

  alias Varsel.Accounts.User
  alias Varsel.CVE
  alias Varsel.CVE.CveRecord

  @year Date.utc_today().year

  setup do
    Application.put_env(:varsel, :hex_stub_packages, ["test_lib"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)
  end

  defp register_user(handle) do
    Ash.create!(
      User,
      %{
        user_info: %{
          "sub" => System.unique_integer([:positive]),
          "preferred_username" => handle,
          "name" => handle,
          "email" => "#{handle}@example.com"
        },
        oauth_tokens: %{"access_token" => "gho_token"}
      },
      action: :register_with_github,
      authorize?: false
    )
  end

  # The first-ever user auto-becomes POC, so make one throwaway POC first, then
  # build the actors we actually want with explicit roles.
  defp actors do
    register_user("bootstrap_poc")

    poc =
      "poc" |> register_user() |> Ash.update!(%{role: :poc}, action: :set_role, authorize?: false)

    supporter =
      "supporter"
      |> register_user()
      |> Ash.update!(%{role: :supporter}, action: :set_role, authorize?: false)

    {poc, supporter}
  end

  defp reservation_json(cve_id) do
    %{
      "cve_id" => cve_id,
      "cve_year" => to_string(@year),
      "owning_cna" => "EEF",
      "reserved" => "#{@year}-01-01T00:00:00.000Z",
      "state" => "RESERVED"
    }
  end

  defp reserved_record(cve_id) do
    Ash.create!(CveRecord, %{reservation_json: reservation_json(cve_id)},
      action: :reserve,
      authorize?: false
    )
  end

  defp published_record(cve_id) do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{"cveId" => cve_id, "state" => "PUBLISHED"},
      "containers" => %{"cna" => %{"title" => "#{cve_id} title"}}
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  # A schema-valid record: unlike :import, the :update action validates the
  # full CVE record schema, so the minimal fixture above won't do.
  defp valid_published_record(cve_id) do
    org_id = "b33eab0a-aa47-4189-b7ec-b71bbfeee3e3"

    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{
        "cveId" => cve_id,
        "assignerOrgId" => org_id,
        "assignerShortName" => "EEF",
        "state" => "PUBLISHED",
        "datePublished" => "#{@year}-01-02T12:00:00.000Z",
        "dateUpdated" => "#{@year}-01-02T12:00:00.000Z"
      },
      "containers" => %{
        "cna" => %{
          "providerMetadata" => %{"orgId" => org_id},
          "title" => "Test vulnerability",
          "descriptions" => [
            %{"lang" => "en", "value" => "A test vulnerability allowing denial of service."}
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
          "references" => [%{"url" => "https://example.com/advisory"}]
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  describe ":list_all read policy" do
    test "a POC sees records in every state" do
      {poc, _supporter} = actors()
      reserved_record("CVE-#{@year}-0001")
      published_record("CVE-#{@year}-0002")

      states = poc |> then(&CVE.list_all_cve_records!(actor: &1)) |> Enum.map(& &1.state)

      assert :reserved in states
      assert :published in states
    end

    test "a non-POC actor is filtered down to published records" do
      {_poc, supporter} = actors()
      reserved_record("CVE-#{@year}-0003")
      published_record("CVE-#{@year}-0004")

      states = supporter |> then(&CVE.list_all_cve_records!(actor: &1)) |> Enum.map(& &1.state)

      assert states == [:published]
    end

    test "an anonymous actor is filtered down to published records" do
      actors()
      reserved_record("CVE-#{@year}-0005")
      published_record("CVE-#{@year}-0006")

      states = [actor: nil] |> CVE.list_all_cve_records!() |> Enum.map(& &1.state)

      assert states == [:published]
    end

    # The merged /cves console surfaces rejected and pending_update records to
    # POCs — this pins that the read POLICY (not template hiding) keeps them
    # away from everyone else.
    test "rejected and pending_update records stay POC-only" do
      {poc, supporter} = actors()

      "CVE-#{@year}-0015"
      |> reserved_record()
      |> Ash.update!(%{rejection_reason: "seed"}, action: :mark_rejected, authorize?: false)

      published = valid_published_record("CVE-#{@year}-12345")

      updated_json = put_in(published.cve_json, ["containers", "cna", "title"], "Edited title")
      Ash.update!(published, %{cve_json: updated_json}, action: :update, authorize?: false)

      for actor <- [supporter, nil] do
        states = [actor: actor] |> CVE.list_all_cve_records!() |> Enum.map(& &1.state)
        assert states == [], "expected no visible records for #{inspect(actor)}"
      end

      poc_states = [actor: poc] |> CVE.list_all_cve_records!() |> Enum.map(& &1.state)
      assert :rejected in poc_states
      assert :pending_update in poc_states
    end
  end

  describe "admin action authorization (hermetic via Ash.can?)" do
    test "a POC can assign, request_publish, update, and reject" do
      {poc, _supporter} = actors()
      reserved = reserved_record("CVE-#{@year}-0007")
      published = published_record("CVE-#{@year}-0008")

      assert Ash.can?({reserved, :assign}, poc)
      assert Ash.can?({reserved, :reject}, poc)
      assert Ash.can?({published, :update}, poc)
    end

    test "a supporter cannot assign, update, or reject" do
      {_poc, supporter} = actors()
      reserved = reserved_record("CVE-#{@year}-0009")
      published = published_record("CVE-#{@year}-0010")

      refute Ash.can?({reserved, :assign}, supporter)
      refute Ash.can?({reserved, :reject}, supporter)
      refute Ash.can?({published, :update}, supporter)
    end

    test "an anonymous actor cannot assign, update, or reject" do
      actors()
      reserved = reserved_record("CVE-#{@year}-0011")
      published = published_record("CVE-#{@year}-0012")

      refute Ash.can?({reserved, :assign}, nil)
      refute Ash.can?({published, :update}, nil)
    end
  end

  describe "public read is unchanged" do
    test ":list_published still returns only published records for anyone" do
      actors()
      reserved_record("CVE-#{@year}-0013")
      published_record("CVE-#{@year}-0014")

      states = [actor: nil] |> CVE.list_published_cve_records!() |> Enum.map(& &1.state)

      assert states == [:published]
    end
  end
end
