# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.OsvAgreementTest do
  @moduledoc """
  A published record answers "is this version affected?" twice: through
  `affected[].versions[]` for a CVE consumer, and through the converted OSV
  document for an OSV one. The two must agree, or the same vulnerability reads
  differently depending on which database you ask.

  Each shape below is resolved both ways, per version, and compared:
  `Varsel.CVE.VersionResolution` against `Varsel.Test.OsvEvaluator`, which
  transcribes the OSV schema's own `IsVulnerable` pseudocode.

  `unknown` has no OSV representation, so those versions are exempt.
  """
  use ExUnit.Case, async: true

  alias Varsel.CVE.OsvConverter
  alias Varsel.CVE.VersionResolution
  alias Varsel.Test.OsvEvaluator

  @probe ~w(0.9.0 1.0.0 1.2.0 1.5.2 1.5.3 1.6.0 2.0.0 3.0.0)

  defp affected_entry(default_status, versions) do
    %{
      "vendor" => "acme",
      "product" => "acme",
      "packageURL" => "pkg:hex/acme",
      "collectionURL" => "https://repo.hex.pm",
      "defaultStatus" => default_status,
      "versions" => versions
    }
  end

  defp record(entry) do
    %{
      "cveMetadata" => %{
        "cveId" => "CVE-2026-1",
        "datePublished" => "2026-01-01T00:00:00.000Z",
        "state" => "PUBLISHED"
      },
      "containers" => %{
        "cna" => %{
          "descriptions" => [%{"lang" => "en", "value" => "x"}],
          "affected" => [entry]
        }
      }
    }
  end

  defp assert_agrees(default_status, versions) do
    entry = affected_entry(default_status, versions)
    osv_result = OsvConverter.convert(record(entry))

    for version <- @probe do
      cve = VersionResolution.resolve(versions, default_status, version)
      osv = osv_verdict(osv_result, version)

      case {cve, osv} do
        # An unknown answer has no OSV counterpart to compare against.
        {{:ok, :unknown}, _} ->
          :ok

        {{:ok, :affected}, verdict} ->
          assert verdict == true, "#{version}: record says affected, OSV says #{inspect(verdict)}"

        {{:ok, :unaffected}, verdict} ->
          assert verdict in [false, :skipped],
                 "#{version}: record says unaffected, OSV says #{inspect(verdict)}"
      end
    end
  end

  # `:skipped` when the record has no OSV representation, which is itself an
  # answer: nothing is affected.
  defp osv_verdict({:skip, _reason}, _version), do: :skipped

  defp osv_verdict({:ok, osv}, version) do
    osv["affected"]
    |> List.wrap()
    |> Enum.find(&(&1["package"]["ecosystem"] == "Hex"))
    |> case do
      nil -> :skipped
      entry -> OsvEvaluator.vulnerable?(entry, version, :semver)
    end
  end

  defp affected(version, less_than) do
    %{
      "version" => version,
      "lessThan" => less_than,
      "status" => "affected",
      "versionType" => "semver"
    }
  end

  defp unaffected(version) do
    %{
      "version" => version,
      "lessThan" => "*",
      "status" => "unaffected",
      "versionType" => "semver"
    }
  end

  describe "an unaffected default" do
    test "one affected range" do
      assert_agrees("unaffected", [affected("1.0.0", "1.5.3")])
    end

    test "two affected ranges" do
      assert_agrees("unaffected", [affected("1.0.0", "1.2.0"), affected("2.0.0", "3.0.0")])
    end

    test "an open affected range" do
      assert_agrees("unaffected", [affected("1.0.0", "*")])
    end

    test "an inclusive upper bound" do
      assert_agrees("unaffected", [
        %{
          "version" => "1.0.0",
          "lessThanOrEqual" => "1.5.2",
          "status" => "affected",
          "versionType" => "semver"
        }
      ])
    end

    test "no rows at all" do
      assert_agrees("unaffected", [])
    end
  end

  describe "an unknown default" do
    test "an affected range beside the fix-carrying span" do
      assert_agrees("unknown", [affected("1.0.0", "1.5.3"), unaffected("1.5.3")])
    end

    test "no rows at all" do
      assert_agrees("unknown", [])
    end
  end

  describe "an affected default" do
    test "no rows at all, so every version is affected" do
      assert_agrees("affected", [])
    end

    test "one fix-carrying span" do
      assert_agrees("affected", [unaffected("1.5.3")])
    end

    test "several fix-carrying spans" do
      assert_agrees("affected", [unaffected("1.2.0"), unaffected("3.0.0")])
    end
  end

  describe "a changes[] chain" do
    @chain [
      %{"at" => "1.2.0", "status" => "unaffected"},
      %{"at" => "2.0.0", "status" => "affected"},
      %{"at" => "3.0.0", "status" => "unaffected"}
    ]

    # A re-introduction is an `introduced` event, whatever the scheme.
    test "under an unaffected default" do
      assert_agrees("unaffected", [Map.put(affected("1.0.0", "*"), "changes", @chain)])
    end

    test "under an affected default" do
      assert_agrees("affected", [Map.put(affected("0", "*"), "changes", @chain)])
    end
  end
end
